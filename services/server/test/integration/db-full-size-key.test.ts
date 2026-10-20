// Full-size HQC-256 keys are stored only where key material belongs; every
// identifier is a 64-character client id, enforced by the schema.

import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { test } from "node:test";
import { DB } from "../../src/server/db/api";
import { q } from "../../src/server/db/pg";
import { createUser } from "../helpers/fixtures";
import { closePg, requirePg } from "../pg-helper";
import { peerId } from "../reference/protocol/identity";

test.before(requirePg);

const PUBLIC_KEY_BYTES = 7237;

const bigPk = () => crypto.randomBytes(PUBLIC_KEY_BYTES).toString("hex");

const tag = () => crypto.randomBytes(4).toString("hex");

test("a full-size key survives every table that legitimately holds one", async () => {
  const pk = bigPk();
  const id = peerId(pk);
  const name = `bigkey_${tag()}`;

  await createUser(id, pk, name);
  assert.equal(await DB.identityKey(id), pk, "the key is served back intact");
  assert.equal(await DB.getUsername(id), name);

  const medium = bigPk();
  const oneTime = [
    { id: 0, prekey: bigPk() },
    { id: 1, prekey: bigPk() },
  ];
  await DB.putPrekeyBundle(id, medium, oneTime);
  const claimed = await DB.claimPrekey(id);
  assert.equal(claimed?.medium, medium, "a full-size medium-term key round-trips");
  assert.equal(claimed?.oneTime?.prekey, oneTime[0]!.prekey, "and a one-time one");
  assert.equal(claimed?.oneTime?.id, 0, "with the client's own index for it");
  assert.equal(await DB.countOneTimePrekeys(id), 1, "the claimed key is consumed");

  await DB.deleteUser(id);
  assert.equal(await DB.identityKey(id), null, "and the key goes with the account");
});

test("users refuses a row whose key does not hash to its id", async () => {
  const id = peerId(bigPk());
  await assert.rejects(
    () => q(`INSERT INTO users (id, identity_pk) VALUES ($1, $2)`, [id, bigPk()]),
    /users_check|violates check constraint/,
    "a key that does not hash to the id must be refused",
  );
});

test("users refuses an id that is not 64 hex characters", async () => {
  const pk = bigPk();
  for (const bad of [pk, pk.slice(0, 63), peerId(pk).toUpperCase(), "g".repeat(64)]) {
    await assert.rejects(
      () => q(`INSERT INTO users (id, identity_pk) VALUES ($1, $2)`, [bad, pk]),
      /violates check constraint/,
      `${bad.slice(0, 16)}… (${bad.length} chars) must be refused as an id`,
    );
  }
});

test("the identity, graph and ACL tables are keyed by a 64-character id", async () => {
  const [pkA, pkB] = [bigPk(), bigPk()];
  const [a, b] = [peerId(pkA), peerId(pkB)];
  const id = tag();
  const [na, nb] = [`big_a_${id}`, `big_b_${id}`];

  await createUser(a, pkA, na);
  await createUser(b, pkB, nb);

  await DB.setUsername(a, `big_a2_${id}`);
  assert.equal(await DB.getUsername(a), `big_a2_${id}`);

  await DB.invite(a, nb);
  assert.equal((await DB.getMyInvites(b)).length, 1);
  assert.ok(await DB.acceptInvite(a, b));
  assert.ok(await DB.areFriends(a, b), "friendship pair key");

  await DB.deleteUser(a);
  await DB.deleteUser(b);
});

test("the ephemeral tier is keyed by id too", async () => {
  const pk = bigPk();
  const a = peerId(pk);
  await DB.ensureUser(a, pk);

  await DB.setPushToken(a, "ios", "production", "tok-1");
  await DB.setPushToken(a, "ios", "production", "tok-2");
  assert.equal((await DB.getPushToken(a))?.token, "tok-2");

  const first = await DB.startAuthChallenge(a, "source", "proof-1");
  const second = await DB.startAuthChallenge(a, "source", "proof-2");
  assert.deepEqual((await DB.openAuthChallenges(a)).map((c) => c.proof).sort(), ["proof-1", "proof-2"]);
  assert.ok(await DB.spendAuthChallenge(a, second));
  assert.ok(!(await DB.spendAuthChallenge(a, second)));
  assert.ok(await DB.spendAuthChallenge(a, first));

  const token = await DB.mintSessionToken(a);
  assert.equal((await DB.resolveSessionToken(token))?.id, a);

  assert.equal(await DB.bumpCounter(`init:pk:${a}`, 60), 1);
  assert.equal(await DB.bumpCounter(`init:pk:${a}`, 60), 2);
  await DB.clearCounter(`init:pk:${a}`);

  await DB.deleteUser(a);
});

test.after(closePg);
