// The caps that bound one account's friend graph and server work.

import assert from "node:assert/strict";
import { test } from "node:test";
import { setLogLevel } from "../../src/common/logger";
import { peerId } from "../../src/protocol/identity";
import { DB } from "../../src/server/db/api";
import { closePg, requirePg } from "../pg-helper";

test.before(requirePg);

setLogLevel("silent");

const PK = (b: string) => b.repeat(64);
const ME = peerId(PK("1a"));
const A = peerId(PK("2b"));
const B = peerId(PK("3c"));

test("countFriends is what the cap reads, and it counts both sides", async () => {
  for (const id of [ME, A, B]) await DB.deleteUser(id).catch(() => {});
  await DB.ensureUser(ME, PK("1a"));
  await DB.ensureUser(A, PK("2b"));
  await DB.ensureUser(B, PK("3c"));

  assert.equal(await DB.countFriends(ME), 0);

  // A friendship is one row naming both members, so it must count for each of
  // them — a cap that only saw the rows a user created would let an account be
  // pushed past its ceiling by other people accepting.
  await DB.createFriendship(ME, A);
  assert.equal(await DB.countFriends(ME), 1);
  assert.equal(await DB.countFriends(A), 1);

  await DB.createFriendship(B, ME);
  assert.equal(await DB.countFriends(ME), 2, "counted regardless of who initiated");

  for (const id of [ME, A, B]) await DB.deleteUser(id);
  assert.equal(await DB.countFriends(ME), 0);
});

test("the daily invite counter windows and resets", async () => {
  // Reuses `rate_counters`, the table already behind /auth/init — no new
  // storage, and the same expiry semantics.
  const key = `invite:day:${ME}`;
  await DB.clearCounter(key);
  assert.equal(await DB.bumpCounter(key, 86400), 1);
  assert.equal(await DB.bumpCounter(key, 86400), 2);
  await DB.clearCounter(key);
  assert.equal(await DB.bumpCounter(key, 86400), 1, "a cleared window starts over");
  await DB.clearCounter(key);
});

test.after(async () => {
  for (const id of [ME, A, B]) await DB.deleteUser(id).catch(() => {});
  await closePg();
});
