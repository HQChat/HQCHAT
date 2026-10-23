// The core pads payloads (core/hqchat-protocol/src/padding.rs); the reference
// client must read what it pads, and refuse what it never would.

import assert from "node:assert/strict";
import { test } from "node:test";
import { unpad } from "../reference/protocol/aead";

const pad = (b: Buffer) => {
  const len = Math.ceil((b.length + 1) / 256) * 256;
  const out = Buffer.alloc(len);
  b.copy(out);
  out[b.length] = 0x80;
  return out;
};

test("what the core pads, the reference reads back", () => {
  for (const n of [0, 1, 255, 256, 1000]) {
    const text = Buffer.alloc(n, 0x80);
    assert.deepEqual(unpad(pad(text)), text, `${n}`);
  }
});

test("what the core could not have padded is refused", () => {
  assert.throws(() => unpad(Buffer.alloc(0)));
  assert.throws(() => unpad(Buffer.alloc(256)), "no marker");
  assert.throws(() => unpad(Buffer.alloc(255, 1)), "not a whole block");
  const long = Buffer.alloc(512);
  long[0] = 0x80;
  assert.throws(() => unpad(long), "a whole block of nothing but padding");
});
