import assert from "node:assert/strict";
import { test } from "node:test";
import { DB } from "../../src/server/db/api";

const ID = "a".repeat(64);

const REJECTED = [
  "evil:user",
  "has space",
  "tab\tuser",
  "new\nline",
  "dash-name",
  "dot.name",
  "emoji😀",
  "ab",
  "x".repeat(33),
  "",
];

for (const name of REJECTED) {
  test(`setUsername rejects ${JSON.stringify(name)} before any query`, async () => {
    await assert.rejects(() => DB.setUsername(ID, name), /INVALID_USERNAME/);
  });
}

test("a reserved username is refused to anyone but its owner", async () => {
  await assert.rejects(() => DB.setUsername(ID, "helper", null), /USERNAME_RESERVED/);
  await assert.rejects(() => DB.setUsername(ID, "Admin", "b".repeat(64)), /USERNAME_RESERVED/);
});
