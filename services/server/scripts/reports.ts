// The moderation queue and its dispositions (docs/runbooks/moderation.md).
//
//   hqcat-ops reports                                  (on the app host)
//   hqcat-ops reports <report-id> <disposition>
//
// App Store Guideline 1.2 requires acting on reported content within 24 hours.
// A new report announces itself through `logger.event` (an unthrottled Sentry
// message) and is worked through here.
//
// ⚠️ Reading the queue deletes lapsed rows: `DB.listOpenReports` sweeps
// `expires_at` first, because the 90-day deletion is a published promise.
//
// ⚠️ An excerpt is not evidence. It is the reporter's own plaintext copy,
// uploaded by consent; nothing can tell a genuine one from an invented one.
// The output says so on every row.

import "../src/common/config";
import { DB } from "../src/server/db/api";
import { disconnect } from "../src/server/db/pg";
import { EMQX } from "../src/server/emqx";

/** What an operator may record; mirrors the CHECK on reports.disposition. */
export const DISPOSITIONS = ["no-action", "warned", "ejected", "banned"] as const;

const short = (id: string | null) => (id ? `${id.slice(0, 12)}…` : "(deleted account)");

/** Prints the open queue and returns its length. */
export async function queue(limit = 100): Promise<number> {
  const rows = await DB.listOpenReports(limit);
  console.log("");
  if (!rows.length) {
    console.log("no open reports.");
    console.log("");
    return 0;
  }
  console.log(`${rows.length} open report(s), oldest first:`);
  console.log("");
  for (const r of rows) {
    // The count is the only question these rows answer that a single report
    // cannot, and it is the one that decides between a word and an ejection.
    const repeat = r.againstSubject > 1 ? `  ⚠️ ${r.againstSubject} reports against this account` : "";
    console.log(`  ${r.id}`);
    console.log(`    ${r.createdAt}  ${r.category}`);
    console.log(`    against ${short(r.reportedId)}   by ${short(r.reporterId)}${repeat}`);
    console.log(
      `    conversation ${r.conversationId.slice(0, 16)}…` +
        (r.messageId ? `  message ${r.messageId.slice(0, 16)}…` : "") +
        (r.hasFrame ? "  [frame attached]" : ""),
    );
    if (r.note) console.log(`    they said: ${r.note}`);
    if (r.excerpt) {
      console.log(`    handed in (UNVERIFIED — the reporter's own copy, not proof of what was said):`);
      for (const line of r.excerpt.split("\n")) console.log(`      | ${line}`);
    }
    console.log("");
  }
  console.log("to record a decision:");
  console.log(`  hqcat-ops reports <report-id> <${DISPOSITIONS.join("|")}>`);
  console.log("");
  console.log("  ejected  disconnects their live session");
  console.log("  banned   deletes their account and disconnects it (a reinstall is a new identity)");
  console.log("");
  return rows.length;
}

/** What a disposition does to the reported account; injectable for tests. */
export interface Enforcement {
  kick(id: string): Promise<boolean>;
  deleteUser(id: string): Promise<void>;
}

const live: Enforcement = { kick: (id) => EMQX.kick(id), deleteUser: (id) => DB.deleteUser(id) };

/** Records a decision and enforces it. Refuses to overwrite a decision somebody already made. */
export async function resolve(id: string, disposition: string, enforce: Enforcement = live): Promise<boolean> {
  if (!(DISPOSITIONS as readonly string[]).includes(disposition)) {
    console.error(`unknown disposition "${disposition}" — one of: ${DISPOSITIONS.join(", ")}`);
    return false;
  }
  const reported = await DB.resolveReport(id, disposition);
  if (!reported) {
    console.log(`⛔️ ${id} is not an open report — unknown id, or somebody has already handled it`);
    return false;
  }
  if (disposition === "banned") await enforce.deleteUser(reported);
  if (disposition === "banned" || disposition === "ejected") {
    if (!(await enforce.kick(reported))) console.log(`⚠️ could not disconnect ${short(reported)}; it may be offline`);
  }
  console.log(`✅ ${id} → ${disposition}`);
  return true;
}

async function main(): Promise<void> {
  const [id, disposition] = process.argv.slice(2);
  if (id && disposition) {
    const ok = await resolve(id, disposition);
    await disconnect();
    process.exit(ok ? 0 : 1);
  }
  if (id) {
    console.error("usage: reports.ts [<report-id> <disposition>]");
    await disconnect();
    process.exit(1);
  }
  await queue();
  await disconnect();
}

if (require.main === module) {
  main().catch(async (e) => {
    console.error(`[reports] ${(e as Error).message}`);
    await disconnect();
    process.exit(1);
  });
}
