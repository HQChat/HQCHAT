import assert from "node:assert/strict";
import { test } from "node:test";
import { APPROVED, STUCK, buildProblem, versionState } from "./asc-review.mjs";

const build = (attributes) => ({ attributes: { version: "42", ...attributes } });

test("the current state attribute wins over the deprecated one", () => {
  assert.equal(versionState({ attributes: { appVersionState: APPROVED, appStoreState: "IN_REVIEW" } }), APPROVED);
  assert.equal(versionState({ attributes: { appStoreState: "IN_REVIEW" } }), "IN_REVIEW");
  assert.equal(versionState(null), null);
});

test("approval is not a stuck state", () => {
  assert.ok(!STUCK.has(APPROVED));
  assert.ok(STUCK.has("REJECTED"));
});

test("a processed build with a compliance answer can be submitted", () => {
  assert.equal(buildProblem(build({ processingState: "VALID", usesNonExemptEncryption: true })), null);
  assert.equal(buildProblem(build({ processingState: "VALID", usesNonExemptEncryption: false })), null);
});

test("export compliance is never guessed", () => {
  assert.match(buildProblem(build({ processingState: "VALID" })), /export compliance/);
  assert.match(buildProblem(build({ processingState: "VALID", usesNonExemptEncryption: null })), /export compliance/);
});

test("unprocessed, invalid and expired builds are refused", () => {
  assert.match(buildProblem(build({ processingState: "PROCESSING", usesNonExemptEncryption: true })), /PROCESSING/);
  assert.match(buildProblem(build({ processingState: "INVALID", usesNonExemptEncryption: true })), /INVALID/);
  assert.match(
    buildProblem(build({ processingState: "VALID", expired: true, usesNonExemptEncryption: true })),
    /expired/,
  );
});
