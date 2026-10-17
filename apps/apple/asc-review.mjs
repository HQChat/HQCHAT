// App Review for the iOS app, driven from App Store Connect's API so the server
// release can wait for Apple's approval (.github/workflows/app-store.yml):
//
//   ASC_KEY_ID=… ASC_ISSUER_ID=… ASC_KEY_P8=… node asc-review.mjs <command> <bundle id> …
//
//   submit  <bundle id> [version] [what's new]
//           Submits the newest processed build of `version` (default: the
//           newest build uploaded) for review, with a MANUAL release: once
//           approved it waits in "Pending Developer Release" until `release`.
//           Waits up to 45 minutes for a fresh upload to finish processing.
//           Prints the version submitted.
//   state   <bundle id> <version>
//           Prints the version's App Store state, e.g. WAITING_FOR_REVIEW,
//           PENDING_DEVELOPER_RELEASE, READY_FOR_SALE, REJECTED.
//   release <bundle id> <version>
//           Releases an approved version to the App Store. Refuses any version
//           that is not PENDING_DEVELOPER_RELEASE.
import { pathToFileURL } from "node:url";
import { API, getAll, parseVersion, token } from "./asc-next.mjs";

const PLATFORM = "IOS";
/** Approved by Apple, waiting for us: the state that releases the server. */
export const APPROVED = "PENDING_DEVELOPER_RELEASE";
/** States Apple will not move on from without us. */
export const STUCK = new Set(["REJECTED", "METADATA_REJECTED", "DEVELOPER_REJECTED", "INVALID_BINARY"]);
const PROCESSING_WAIT_MS = 45 * 60 * 1000;
const PROCESSING_POLL_MS = 60 * 1000;

/** The state of a version, preferring the current attribute over the deprecated one. */
export function versionState(v) {
  return v?.attributes?.appVersionState ?? v?.attributes?.appStoreState ?? null;
}

/**
 * Why a build cannot be submitted, or null when it can. Export compliance is
 * the user's legal answer, never guessed here: an unanswered build is refused.
 */
export function buildProblem(build) {
  const a = build?.attributes ?? {};
  if (a.processingState !== "VALID") return `build ${a.version} is ${a.processingState ?? "not processed"}`;
  if (a.expired) return `build ${a.version} has expired`;
  if (a.usesNonExemptEncryption == null) {
    return (
      `build ${a.version} has no export compliance answer: answer it once in App Store Connect ` +
      `(TestFlight → the build → Manage), or set ITSAppUsesNonExemptEncryption in the app's Info.plist`
    );
  }
  return null;
}

let jwt;
function auth() {
  const { ASC_KEY_ID: keyId, ASC_ISSUER_ID: issuerId, ASC_KEY_P8: p8 } = process.env;
  if (!keyId || !issuerId || !p8) throw new Error("ASC_KEY_ID, ASC_ISSUER_ID and ASC_KEY_P8 must be set");
  jwt ??= token({ keyId, issuerId, p8 });
  return jwt;
}

async function call(method, path, data) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: { Authorization: `Bearer ${auth()}`, "Content-Type": "application/json" },
    body: data ? JSON.stringify({ data }) : undefined,
  });
  if (!res.ok) throw new Error(`App Store Connect ${res.status} on ${method} ${path}: ${await res.text()}`);
  return res.status === 204 ? null : res.json();
}

async function appId(bundleId) {
  const apps = await getAll(auth(), `/v1/apps?filter[bundleId]=${encodeURIComponent(bundleId)}&fields[apps]=bundleId`);
  const app = apps.find((a) => a.attributes.bundleId === bundleId);
  if (!app) throw new Error(`no app with bundle id ${bundleId} in App Store Connect`);
  return app.id;
}

async function storeVersion(app, version) {
  const found = await getAll(
    auth(),
    `/v1/apps/${app}/appStoreVersions?filter[platform]=${PLATFORM}&filter[versionString]=${encodeURIComponent(version)}`,
  );
  return found[0] ?? null;
}

/** The newest build of `version` (any version when null), with its version string. */
async function newestBuild(app, version) {
  const filter = version ? `&filter[preReleaseVersion.version]=${encodeURIComponent(version)}` : "";
  const page = await call(
    "GET",
    `/v1/builds?filter[app]=${app}&filter[preReleaseVersion.platform]=${PLATFORM}${filter}` +
      `&sort=-uploadedDate&limit=1&include=preReleaseVersion` +
      `&fields[builds]=version,processingState,expired,usesNonExemptEncryption,preReleaseVersion` +
      `&fields[preReleaseVersions]=version`,
  );
  const build = page.data[0];
  if (!build) return null;
  const train = page.included?.find((i) => i.id === build.relationships?.preReleaseVersion?.data?.id);
  return { build, version: train?.attributes?.version ?? version };
}

async function submit(bundleId, requested, whatsNew) {
  if (requested && !parseVersion(requested)) throw new Error(`"${requested}" is not a version`);
  const app = await appId(bundleId);

  // A fresh upload takes a while to process; wait for it rather than fail.
  let found;
  for (const deadline = Date.now() + PROCESSING_WAIT_MS; ; ) {
    found = await newestBuild(app, requested);
    if (!found) throw new Error(`no build${requested ? ` of ${requested}` : ""} in App Store Connect`);
    if (found.build.attributes.processingState !== "PROCESSING" || Date.now() > deadline) break;
    console.error(`build ${found.build.attributes.version} is still processing…`);
    await new Promise((r) => setTimeout(r, PROCESSING_POLL_MS));
  }
  const problem = buildProblem(found.build);
  if (problem) throw new Error(problem);
  const { build, version } = found;
  console.error(`submitting ${version} (${build.attributes.version})`);

  // The App Store version: created, or brought to a manual release on this build.
  let v = await storeVersion(app, version);
  if (!v) {
    v = (
      await call("POST", "/v1/appStoreVersions", {
        type: "appStoreVersions",
        attributes: { platform: PLATFORM, versionString: version, releaseType: "MANUAL" },
        relationships: {
          app: { data: { type: "apps", id: app } },
          build: { data: { type: "builds", id: build.id } },
        },
      })
    ).data;
  } else {
    const state = versionState(v);
    if (!["PREPARE_FOR_SUBMISSION", "DEVELOPER_REJECTED", "REJECTED", "METADATA_REJECTED"].includes(state)) {
      throw new Error(`${version} is ${state} in App Store Connect; nothing to submit`);
    }
    await call("PATCH", `/v1/appStoreVersions/${v.id}`, {
      type: "appStoreVersions",
      id: v.id,
      attributes: { releaseType: "MANUAL" },
    });
    await call("PATCH", `/v1/appStoreVersions/${v.id}/relationships/build`, { type: "builds", id: build.id });
  }

  if (whatsNew) {
    const locs = await getAll(auth(), `/v1/appStoreVersions/${v.id}/appStoreVersionLocalizations`);
    for (const loc of locs) {
      await call("PATCH", `/v1/appStoreVersionLocalizations/${loc.id}`, {
        type: "appStoreVersionLocalizations",
        id: loc.id,
        attributes: { whatsNew },
      });
    }
  }

  // An open (unsubmitted) review submission is reused: there can be only one.
  const open = await getAll(
    auth(),
    `/v1/reviewSubmissions?filter[app]=${app}&filter[platform]=${PLATFORM}&filter[state]=READY_FOR_REVIEW`,
  );
  const submission =
    open[0] ??
    (
      await call("POST", "/v1/reviewSubmissions", {
        type: "reviewSubmissions",
        attributes: { platform: PLATFORM },
        relationships: { app: { data: { type: "apps", id: app } } },
      })
    ).data;
  const items = await getAll(auth(), `/v1/reviewSubmissions/${submission.id}/items?include=appStoreVersion`);
  if (!items.some((i) => i.relationships?.appStoreVersion?.data?.id === v.id)) {
    await call("POST", "/v1/reviewSubmissionItems", {
      type: "reviewSubmissionItems",
      relationships: {
        reviewSubmission: { data: { type: "reviewSubmissions", id: submission.id } },
        appStoreVersion: { data: { type: "appStoreVersions", id: v.id } },
      },
    });
  }
  await call("PATCH", `/v1/reviewSubmissions/${submission.id}`, {
    type: "reviewSubmissions",
    id: submission.id,
    attributes: { submitted: true },
  });
  console.log(version);
}

async function state(bundleId, version) {
  const v = await storeVersion(await appId(bundleId), version);
  console.log(v ? versionState(v) : "NONE");
}

async function release(bundleId, version) {
  const v = await storeVersion(await appId(bundleId), version);
  if (!v) throw new Error(`no App Store version ${version}`);
  if (versionState(v) !== APPROVED) {
    throw new Error(`${version} is ${versionState(v)}, not ${APPROVED}: refusing to release it`);
  }
  await call("POST", "/v1/appStoreVersionReleaseRequests", {
    type: "appStoreVersionReleaseRequests",
    relationships: { appStoreVersion: { data: { type: "appStoreVersions", id: v.id } } },
  });
  console.log(`released ${version}`);
}

const COMMANDS = { submit, state, release };

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [command, bundleId, ...rest] = process.argv.slice(2);
  const run = COMMANDS[command];
  if (!run || !bundleId) {
    console.error("usage: node asc-review.mjs <submit|state|release> <bundle id> [version] [what's new]");
    process.exit(2);
  }
  run(bundleId, ...rest).catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
