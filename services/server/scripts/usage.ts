// How many people use the app, as counts (src/server/db/usage.ts).
//
//   hqcat-ops usage                                     (on the app host)
//
// Online now comes from EMQX; active and peak from the server's own daily
// counts; accounts from `users`; downloads from App Store Connect, cached in
// `app_downloads`. The helper bot and the sims are never counted. Days are UTC.

import "../src/common/config";
import { refreshDownloads, salesConfig } from "../src/server/appstore-sales";
import { DB } from "../src/server/db/api";
import { disconnect } from "../src/server/db/pg";
import { EMQX } from "../src/server/emqx";

const row = (label: string, value: string) => `  ${label.padEnd(22)}${value}`;

/** The App Store lines: refreshes the cache first, then reads it back. */
async function downloadLines(today: string): Promise<string[]> {
  let cfg: ReturnType<typeof salesConfig>;
  try {
    cfg = salesConfig();
  } catch (e) {
    return [row("App Store downloads", `misconfigured: ${(e as Error).message}`)];
  }
  if (!cfg) return [row("App Store downloads", "not configured (ASC_SALES_*, docs/runbooks/usage.md)")];
  const notes: string[] = [];
  try {
    const r = await refreshDownloads(cfg, DB, today);
    if (r.pending.length) notes.push(`not published yet: ${r.pending.join(", ")}`);
    if (r.malformed) notes.push(`⚠️ ${r.malformed} report row(s) could not be read and were not counted`);
    if (r.remaining) notes.push(`${r.remaining} older day(s) still to fetch; run again`);
  } catch (e) {
    notes.push(`⚠️ refresh failed, showing what is cached: ${(e as Error).message}`);
  }
  const { latest, total } = await DB.downloadTotals();
  const latestText = latest ? `${latest.units} on ${latest.day}` : "none yet";
  return [
    row("App Store downloads", `${latestText}, ${total} all time (since ${cfg.start})`),
    ...notes.map((n) => `    ${n}`),
  ];
}

/** The whole report, as lines. Rolls finished days up first, so yesterday is final. */
export async function usageReport(): Promise<string[]> {
  await DB.rollupUsage();
  const online = await EMQX.onlineCount(await DB.serviceIds());
  const s = await DB.usageSummary();
  const week = s.lastWeek;
  const range = week.length ? `   (${week[0]?.day} … ${week[week.length - 1]?.day})` : "";
  return [
    "",
    `usage on ${s.today} (UTC); the helper bot and the sims are not counted`,
    "",
    row("online now", online === null ? "unknown (EMQX API not configured or not answering)" : String(online)),
    row("active today", `${s.activeToday}   accounts signed in since 00:00 UTC`),
    row("peak online today", String(s.peakOnlineToday)),
    row("active, last 7 days", `${week.map((d) => d.active).join(" ")}${range}`),
    row("peak, last 7 days", week.map((d) => d.peakOnline).join(" ")),
    row("accounts", `${s.accounts}   +${s.accountsToday} today`),
    ...(await downloadLines(s.today)),
    "",
  ];
}

async function main(): Promise<void> {
  if (process.argv.length > 2) {
    console.error("usage: usage.ts");
    await disconnect();
    process.exit(1);
  }
  for (const line of await usageReport()) console.log(line);
  await disconnect();
}

if (require.main === module) {
  main().catch(async (e) => {
    console.error(`[usage] ${(e as Error).message}`);
    await disconnect();
    process.exit(1);
  });
}
