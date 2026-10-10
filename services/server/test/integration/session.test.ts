import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { test } from "node:test";
import { DB } from "../../src/server/db/api";
import { one, q } from "../../src/server/db/pg";
import { closePg, requirePg } from "../pg-helper";

test.before(requirePg);

const ID = "aa".repeat(32);
const hash = (token: string) => crypto.createHash("sha256").update(token).digest("hex");

async function idleSeconds(token: string): Promise<number | null> {
  const row = await one<{ s: number }>(
    `SELECT EXTRACT(epoch FROM expires_at - now())::int AS s FROM sessions WHERE token_hash = $1`,
    [hash(token)],
  );
  return row?.s ?? null;
}

test("a fresh session resolves to its client id", async () => {
  const token = await DB.mintSessionToken(ID);
  assert.deepEqual(await DB.resolveSessionToken(token), { id: ID });
});

test("using a session close to lapsing slides its idle timeout forward", async () => {
  const token = await DB.mintSessionToken(ID);
  await q(`UPDATE sessions SET expires_at = now() + interval '2 seconds' WHERE token_hash = $1`, [hash(token)]);
  assert.equal((await DB.resolveSessionToken(token))?.id, ID);
  const left = await idleSeconds(token);
  assert.ok(left !== null && left > 60, `expected the idle timeout to slide, got ${left}s`);
});

test("an unknown or revoked token resolves to nothing", async () => {
  const token = await DB.mintSessionToken(ID);
  await DB.revokeSessionToken(token);
  assert.equal(await DB.resolveSessionToken(token), null);
  assert.equal(await DB.resolveSessionToken("not-a-token"), null);
});

test("a session past its absolute cap is refused and deleted", async () => {
  const token = await DB.mintSessionToken(ID);
  await q(`UPDATE sessions SET iat = now() - interval '31 days' WHERE token_hash = $1`, [hash(token)]);
  assert.equal(await DB.resolveSessionToken(token), null);
  assert.equal(await idleSeconds(token), null, "the row is deleted, not merely refused");
});

test.after(closePg);
