// The usage counts (src/server/db/usage.ts). What matters beyond the numbers:
// a finished day leaves a count and no ids behind, and the bot and the sims
// never count as people.

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { test } from "node:test";
import { DB } from "../../src/server/db/api";
import { q } from "../../src/server/db/pg";
import { closePg, requirePg } from "../pg-helper";
import { peerId } from "../reference/protocol/identity";

test.before(requirePg);

/** A day no other test or real traffic touches. */
const PAST = "2001-02-03";
const created: string[] = [];
/** A sim's handle (src/sim/main.ts) out of the real fleet's range, so it cannot collide. */
const simHandle = () => `echo_${crypto.randomInt(100_000, 999_999)}`;

async function account(username?: string): Promise<string> {
  const pkHex = crypto.randomBytes(64).toString("hex");
  const id = peerId(pkHex);
  await DB.ensureUser(id, pkHex);
  if (username) await q(`UPDATE users SET username = $2 WHERE id = $1`, [id, username]);
  created.push(id);
  return id;
}

async function wipe(): Promise<void> {
  await q(`DELETE FROM active_today WHERE id = ANY($1::text[])`, [created]);
  await q(`DELETE FROM users WHERE id = ANY($1::text[])`, [created]);
  await q(`DELETE FROM usage_daily WHERE day = $1::date`, [PAST]);
  created.length = 0;
}

test.afterEach(wipe);
test.after(async () => {
  await wipe();
  await closePg();
});

test("an account counts once a day however often it signs in, and the bot never", async () => {
  const before = (await DB.usageSummary()).activeToday;
  const a = await account();
  const bot = await account();
  process.env.BOT_ID = bot;
  try {
    await DB.markActive(a);
    await DB.markActive(a);
    await DB.markActive(bot);
    assert.equal((await DB.usageSummary()).activeToday, before + 1);
  } finally {
    delete process.env.BOT_ID;
  }
});

test("a finished day becomes a count and its ids are deleted; today is left alone", async () => {
  const a = await account();
  const b = await account();
  const sim = await account(simHandle());
  await q(`INSERT INTO active_today (day, id) VALUES ($1::date, $2), ($1::date, $3), ($1::date, $4)`, [
    PAST,
    a,
    b,
    sim,
  ]);
  await DB.markActive(a);

  await DB.rollupUsage();

  const row = await q<{ active: number }>(`SELECT active FROM usage_daily WHERE day = $1::date`, [PAST]);
  assert.equal(row.rows[0]?.active, 2, "two people; the sim is not one");
  const left = await q(`SELECT 1 FROM active_today WHERE day = $1::date`, [PAST]);
  assert.equal(left.rowCount, 0, "no ids may outlive their day");
  const today = await q(`SELECT 1 FROM active_today WHERE id = $1 AND day = (now() AT TIME ZONE 'UTC')::date`, [a]);
  assert.equal(today.rowCount, 1);
});

test("a late row for a rolled-up day is added, not lost", async () => {
  await q(`INSERT INTO active_today (day, id) VALUES ($1::date, $2)`, [PAST, await account()]);
  await DB.rollupUsage();
  await q(`INSERT INTO active_today (day, id) VALUES ($1::date, $2)`, [PAST, await account()]);
  await DB.rollupUsage();
  const row = await q<{ active: number }>(`SELECT active FROM usage_daily WHERE day = $1::date`, [PAST]);
  assert.equal(row.rows[0]?.active, 2);
});

test("today's peak only goes up", async () => {
  const start = (await DB.usageSummary()).peakOnlineToday;
  await DB.notePeakOnline(start + 5);
  await DB.notePeakOnline(start + 2);
  assert.equal((await DB.usageSummary()).peakOnlineToday, start + 5);
  await assert.rejects(() => DB.notePeakOnline(-1), RangeError);
});

test("the week is seven days, oldest first, zeros where nothing was counted", async () => {
  const { lastWeek, today } = await DB.usageSummary();
  assert.equal(lastWeek.length, 7);
  assert.ok(lastWeek.every((d, i) => i === 0 || d.day > lastWeek[i - 1]!.day));
  assert.ok(lastWeek[6]!.day < today);
});

test("accounts leave out the bot and the sims, and count today's", async () => {
  const before = await DB.usageSummary();
  await account();
  await account(simHandle());
  const bot = await account();
  process.env.BOT_ID = bot;
  try {
    const after = await DB.usageSummary();
    assert.equal(after.accounts, before.accounts + 1);
    assert.equal(after.accountsToday, before.accountsToday + 1);
    assert.ok((await DB.serviceIds()).has(bot));
  } finally {
    delete process.env.BOT_ID;
  }
});

test("deleting an account deletes its row in today's list", async () => {
  const a = await account();
  await DB.markActive(a);
  await DB.deleteUser(a);
  const left = await q(`SELECT 1 FROM active_today WHERE id = $1`, [a]);
  assert.equal(left.rowCount, 0);
});

test("downloads are cached per day and summed", async () => {
  await q(`DELETE FROM app_downloads WHERE day BETWEEN '2001-01-01' AND '2001-01-31'`);
  const before = (await DB.downloadTotals()).total;
  await DB.recordDownloads("2001-01-01", 4);
  await DB.recordDownloads("2001-01-02", 3);
  await DB.recordDownloads("2001-01-02", 5); // a re-fetch replaces, never adds
  assert.equal((await DB.downloadTotals()).total, before + 9);
  assert.deepEqual(
    [...(await DB.downloadDaysSince("2001-01-02"))].filter((d) => d < "2001-02-01"),
    ["2001-01-02"],
  );
  await q(`DELETE FROM app_downloads WHERE day BETWEEN '2001-01-01' AND '2001-01-31'`);
});
