// Why a phone would or would not be woken, from the server's own state.
//
//   hqcat-ops check-push <username|id>        (on the app host)
//
// Every step of the push path stops silently when it cannot proceed (no APNs
// config, no registered token, no topic), so this states which step stops.
//
// It cannot see whether the device is currently marked online: that lives in
// the server's memory (`GET /health` reports the size of the set). A token
// here, APNs ready, and no notification means the server believed the device
// was reachable.

import "../src/common/config";
import { isPeerId } from "../src/common/core";
import { keyProblem } from "../src/server/apns";
import { apnsGaps, apnsSummary } from "../src/server/apns-config";
import { DB } from "../src/server/db/api";
import { disconnect, q } from "../src/server/db/pg";

/** Resolve a username or an id to an id. Exported so the resolution half can be
 *  asserted without driving the whole report. */
export async function resolve(who: string): Promise<{ id: string; username: string } | null> {
  if (isPeerId(who)) {
    const row = await q<{ id: string; username: string | null }>(`SELECT id, username FROM users WHERE id = $1`, [who]);
    const r = row.rows[0];
    return r ? { id: r.id, username: r.username ?? "(no handle)" } : null;
  }
  const row = await q<{ id: string; username: string | null }>(`SELECT id, username FROM users WHERE username = $1`, [
    who,
  ]);
  const r = row.rows[0];
  return r ? { id: r.id, username: r.username ?? "(no handle)" } : null;
}

/** Prints whether APNs can send at all and returns the missing settings. */
function configSection(): string[] {
  console.log("");
  console.log(`APNs: ${apnsSummary(process.env)}`);
  // "Set" and "usable" are different questions. A .p8 that OpenSSL will not load
  // passes every presence check and fails every push.
  const keyIssue = keyProblem();
  if (keyIssue && process.env.APNS_KEY_P8?.trim()) {
    console.log(`  ⛔️ ${keyIssue}`);
    console.log("     Set the APNS_KEY_P8 environment secret from the file Apple gave you");
    console.log("     (gh secret set APNS_KEY_P8 --env <environment> < AuthKey_XXXXXXXXXX.p8),");
    console.log("     then run Deploy.");
  }

  const gaps = apnsGaps(process.env);
  if (gaps.length) {
    console.log("");
    console.log("  ⛔️ Nothing below matters until this is fixed: with APNs incomplete,");
    console.log("     ApnsService.send() returns before it builds a request. No device");
    console.log("     is woken, and no error is logged, for any account.");
    console.log("");
    console.log("     The key id, team id and topics belong in the `apns` block of");
    console.log("     infra/environments/<environment>.json; the key itself is the");
    console.log("     APNS_KEY_P8 environment secret, published as apns_key_p8.");
  }
  return gaps;
}

/** Registered devices per platform: nobody having a token is a different problem from one device. */
async function tableSection(): Promise<void> {
  const all = await q<{ platform: string; n: string }>(
    `SELECT platform, count(*)::text AS n FROM push_tokens GROUP BY platform ORDER BY platform`,
  );
  const users = await q<{ n: string }>(`SELECT count(*)::text AS n FROM users`);
  console.log("");
  console.log(`registered devices (of ${users.rows[0]?.n ?? "?"} accounts)`);
  if (all.rows.length === 0) {
    console.log("  none — no device has ever POSTed /push/token.");
    console.log("  The client does that on every successful auth, so zero rows means");
    console.log("  either no build with push has ever signed in, or the entitlement is");
    console.log("  missing and registerForRemoteNotifications never returned a token.");
  } else {
    for (const r of all.rows) console.log(`  ${r.platform}: ${r.n}`);
  }
  console.log("");
  console.log("Pass a username or client id to check one account.");
  console.log("");
}

/** One account's token, topic and conversations, and the verdict. */
async function accountSection(who: { id: string; username: string }, gaps: string[]): Promise<void> {
  console.log("");
  console.log(`@${who.username} = ${who.id}`);

  const token = await DB.getPushToken(who.id);
  if (!token) {
    console.log("  push token: NONE");
    console.log("    → this device cannot be woken at all. The app registers on every");
    console.log("      sign-in (PushManager.requestAndRegister), so a missing row means the");
    console.log("      OS never handed it a token: notification permission denied, or the");
    console.log("      build has no aps-environment entitlement.");
  } else {
    const topic = token.platform === "macos" ? process.env.APNS_TOPIC_MACOS : process.env.APNS_TOPIC_IOS;
    console.log(`  push token: ${token.token.slice(0, 12)}… (${token.platform})`);
    console.log(`  topic for ${token.platform}: ${topic || "UNSET — send() returns silently"}`);
  }

  const friends = await q<{ peer: string; convo_id: string }>(
    `SELECT CASE WHEN id_lo = $1 THEN id_hi ELSE id_lo END AS peer, convo_id
       FROM friendships WHERE id_lo = $1 OR id_hi = $1`,
    [who.id],
  );
  console.log(`  conversations that could wake them: ${friends.rows.length}`);
  for (const f of friends.rows) {
    console.log(`    cv/${f.convo_id.slice(0, 8)}… with ${f.peer.slice(0, 8)}…`);
  }

  console.log("");
  console.log("──");
  if (gaps.length) {
    console.log("APNs is not ready — see the top of this report.");
  } else if (!token) {
    console.log("APNs is ready, but this account has no device to send to.");
  } else {
    console.log("Nothing in the server's state blocks a wake for this account.");
    console.log("If it still does not buzz: the bridge only wakes a member it believes is");
    console.log("OFFLINE. Check `curl 127.0.0.1:8090/health` for the size of that set, and");
    console.log("the journal for a `could not wake` line naming the reason.");
  }
  console.log("");
}

/** The report: APNs readiness, then the device table, or one account (a username or an id). */
export async function report(arg?: string): Promise<void> {
  const gaps = configSection();
  if (!arg) return tableSection();
  const who = await resolve(arg);
  if (!who) {
    console.log(`\nno account "${arg}" — it has never completed /auth/verify.\n`);
    return;
  }
  await accountSection(who, gaps);
}

// Only when this file is the process entry point. Imported, it reports nothing
// and closes no pool — the caller owns both.
if (require.main === module) {
  report(process.argv[2])
    .catch((e) => {
      console.error(e instanceof Error ? e.message : String(e));
      process.exitCode = 1;
    })
    .finally(() => disconnect());
}
