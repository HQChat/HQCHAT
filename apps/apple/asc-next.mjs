// The version and build number of the next iOS or macOS upload, read from App
// Store Connect so every upload is strictly above everything already there for
// that platform: above every TestFlight train and App Store version, and above
// every build number, whichever workflow or Mac uploaded them.
//
//   ASC_KEY_ID=… ASC_ISSUER_ID=… ASC_KEY_P8=… node asc-next.mjs \
//     <bundle id> <IOS|MAC_OS> <project MARKETING_VERSION> <project CURRENT_PROJECT_VERSION> [requested version]
//
// Prints "<version> <build>". Without a requested version, the patch of the
// highest version goes up by one, unless the project already names a higher
// one. A requested version must be higher than every version in App Store
// Connect. The build number is one above the highest build of any version.
import { createPrivateKey, sign } from "node:crypto";
import { pathToFileURL } from "node:url";

const API = "https://api.appstoreconnect.apple.com";

/** Version strings as App Store Connect takes them: one to three integers. */
export function parseVersion(v) {
  const s = String(v ?? "").trim();
  if (!/^\d+(\.\d+){0,2}$/.test(s)) return null;
  const parts = s.split(".").map(Number);
  while (parts.length < 3) parts.push(0);
  return parts;
}

export function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

function highest(versions) {
  return versions.filter((v) => parseVersion(v)).sort(compareVersions).at(-1) ?? null;
}

export function nextVersion({ existing, project, requested }) {
  const top = highest(existing);
  if (requested) {
    if (!parseVersion(requested)) throw new Error(`"${requested}" is not a version (1 to 3 integers, e.g. 3.1.0)`);
    if (top && compareVersions(requested, top) <= 0) {
      throw new Error(`version ${requested} must be higher than ${top}, the highest in App Store Connect`);
    }
    return parseVersion(requested).join(".");
  }
  if (!top) return parseVersion(project)?.join(".") ?? "1.0.0";
  if (parseVersion(project) && compareVersions(project, top) > 0) return parseVersion(project).join(".");
  const [major, minor, patch] = parseVersion(top);
  return `${major}.${minor}.${patch + 1}`;
}

/** Build numbers may be dotted ("45.1"); the leading integer orders them. */
export function nextBuild({ existing, project }) {
  const lead = (b) => Number.parseInt(String(b), 10);
  const numbers = [...existing, project].map(lead).filter(Number.isFinite);
  return Math.max(0, ...numbers) + 1;
}

function token({ keyId, issuerId, p8 }) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  const body = `${b64({ alg: "ES256", kid: keyId, typ: "JWT" })}.${b64({
    iss: issuerId,
    iat: now,
    exp: now + 15 * 60,
    aud: "appstoreconnect-v1",
  })}`;
  const key = createPrivateKey(p8.includes("BEGIN") ? p8 : `-----BEGIN PRIVATE KEY-----\n${p8}\n-----END PRIVATE KEY-----\n`);
  const sig = sign("sha256", Buffer.from(body), { key, dsaEncoding: "ieee-p1363" });
  return `${body}.${sig.toString("base64url")}`;
}

async function getAll(jwt, path) {
  const out = [];
  for (let url = `${API}${path}`; url; ) {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${jwt}` } });
    if (!res.ok) throw new Error(`App Store Connect ${res.status} on ${new URL(url).pathname}: ${await res.text()}`);
    const page = await res.json();
    out.push(...page.data);
    url = page.links?.next;
  }
  return out;
}

/**
 * Why an app record is missing, from what the key can see: every app record
 * with its bundle id and platforms, and whether the bundle id is registered
 * (an identifier without an app record cannot take uploads).
 */
async function notFound(jwt, bundleId) {
  const lines = [`no app record with bundle id ${bundleId} in App Store Connect.`];
  const apps = await getAll(jwt, "/v1/apps?fields[apps]=name,bundleId&limit=200");
  lines.push(apps.length ? "App records this key can see:" : "This key sees no app records.");
  for (const a of apps) {
    const versions = await getAll(jwt, `/v1/apps/${a.id}/appStoreVersions?fields[appStoreVersions]=platform&limit=200`);
    const platforms = [...new Set(versions.map((v) => v.attributes.platform))].join(", ") || "no App Store version yet";
    lines.push(`  ${a.attributes.bundleId}  "${a.attributes.name}"  (${platforms})`);
  }
  const prefix = bundleId.slice(0, bundleId.lastIndexOf("."));
  const ids = await getAll(
    jwt,
    `/v1/bundleIds?filter[identifier]=${encodeURIComponent(prefix)}&fields[bundleIds]=identifier,platform&limit=200`,
  );
  const registered = ids.find((i) => i.attributes.identifier === bundleId);
  lines.push(
    registered
      ? `${bundleId} is registered (${registered.attributes.platform}) but has no app record: create one in App Store Connect → Apps → New App.`
      : `${bundleId} is not registered as an identifier either.`,
  );
  const others = ids.filter((i) => i !== registered).map((i) => `  ${i.attributes.identifier} (${i.attributes.platform})`);
  if (others.length) lines.push(`Identifiers under ${prefix}:`, ...others);
  return lines.join("\n");
}

async function main([bundleId, platform, projectVersion, projectBuild, requested]) {
  const { ASC_KEY_ID: keyId, ASC_ISSUER_ID: issuerId, ASC_KEY_P8: p8 } = process.env;
  if (!keyId || !issuerId || !p8 || !bundleId || !["IOS", "MAC_OS"].includes(platform)) {
    throw new Error("usage: ASC_KEY_ID=… ASC_ISSUER_ID=… ASC_KEY_P8=… node asc-next.mjs <bundle id> <IOS|MAC_OS> <version> <build> [requested]");
  }
  const jwt = token({ keyId, issuerId, p8 });
  const apps = await getAll(jwt, `/v1/apps?filter[bundleId]=${encodeURIComponent(bundleId)}&fields[apps]=bundleId`);
  const app = apps.find((a) => a.attributes.bundleId === bundleId);
  if (!app) throw new Error(await notFound(jwt, bundleId));

  const [trains, storeVersions, builds] = await Promise.all([
    getAll(jwt, `/v1/preReleaseVersions?filter[app]=${app.id}&filter[platform]=${platform}&fields[preReleaseVersions]=version&limit=200`),
    getAll(jwt, `/v1/apps/${app.id}/appStoreVersions?filter[platform]=${platform}&fields[appStoreVersions]=versionString&limit=200`),
    getAll(jwt, `/v1/builds?filter[app]=${app.id}&filter[preReleaseVersion.platform]=${platform}&fields[builds]=version&limit=200`),
  ]);
  const version = nextVersion({
    existing: [...trains.map((t) => t.attributes.version), ...storeVersions.map((v) => v.attributes.versionString)],
    project: projectVersion,
    requested: requested || undefined,
  });
  const build = nextBuild({ existing: builds.map((b) => b.attributes.version), project: projectBuild });
  console.log(`${version} ${build}`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
