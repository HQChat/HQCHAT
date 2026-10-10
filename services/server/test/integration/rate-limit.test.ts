// The counters behind `/auth/init`'s limits and the
// failed-proof alarm. Both are one row with a window, and both are easy to get
// wrong in the same way — a window re-armed on every hit turns a fixed window
// into an unbounded one.

import assert from "node:assert/strict";
import { test } from "node:test";
import { DB } from "../../src/server/db/api";
import { one } from "../../src/server/db/pg";
import { closePg, requirePg } from "../pg-helper";

test.before(requirePg);

test("a counter increments and reports the count after the hit", async () => {
  const key = `test:${Date.now()}:${Math.random()}`;
  assert.equal(await DB.bumpCounter(key, 60), 1);
  assert.equal(await DB.bumpCounter(key, 60), 2);
  assert.equal(await DB.bumpCounter(key, 60), 3);
  await DB.clearCounter(key);
});

const windowSeconds = async (key: string) =>
  (
    await one<{ s: number }>(
      `SELECT EXTRACT(epoch FROM window_ends_at - now())::int AS s FROM rate_counters WHERE key = $1`,
      [key],
    )
  )?.s ?? -1;

test("the window is set once, not re-armed by later hits", async () => {
  // A window re-armed on every hit never closes, so a slow attacker never trips
  // the limit and never falls out of it either.
  const key = `test:${Date.now()}:${Math.random()}`;
  await DB.bumpCounter(key, 100);
  const first = await windowSeconds(key);
  await DB.bumpCounter(key, 5); // a shorter window must not shrink it
  const second = await windowSeconds(key);
  assert.ok(second > 5, `expected the original window to stand, got ttl ${second}`);
  assert.ok(Math.abs(second - first) <= 1, "the window moved when it should not have");
  await DB.clearCounter(key);
});

test("clearing a counter starts the run again", async () => {
  const key = `test:${Date.now()}:${Math.random()}`;
  await DB.bumpCounter(key, 60);
  await DB.bumpCounter(key, 60);
  await DB.clearCounter(key);
  assert.equal(await DB.bumpCounter(key, 60), 1, "a success must reset the failure run");
  await DB.clearCounter(key);
});

test.after(closePg);
