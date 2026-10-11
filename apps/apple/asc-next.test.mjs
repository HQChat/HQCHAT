import assert from "node:assert/strict";
import { test } from "node:test";
import { compareVersions, nextBuild, nextVersion, parseVersion } from "./asc-next.mjs";

test("versions are one to three integers", () => {
  assert.deepEqual(parseVersion("3"), [3, 0, 0]);
  assert.deepEqual(parseVersion("3.1"), [3, 1, 0]);
  assert.deepEqual(parseVersion("3.1.4"), [3, 1, 4]);
  for (const bad of ["", "v3", "3.1.4.1", "3.x", "3.1-beta", undefined]) assert.equal(parseVersion(bad), null);
});

test("versions compare numerically, not as text", () => {
  assert.ok(compareVersions("3.10.0", "3.9.0") > 0);
  assert.equal(compareVersions("3.1", "3.1.0"), 0);
});

test("without a request, the patch of the highest version goes up", () => {
  assert.equal(nextVersion({ existing: ["2.9.9", "3.0.0", "3.0.2"], project: "3.0.0" }), "3.0.3");
  assert.equal(nextVersion({ existing: ["3.0.9", "3.0.10"], project: "3.0.0" }), "3.0.11");
});

test("a project version above App Store Connect is used as is", () => {
  assert.equal(nextVersion({ existing: ["3.0.2"], project: "3.1.0" }), "3.1.0");
});

test("the first upload takes the project version", () => {
  assert.equal(nextVersion({ existing: [], project: "3.0.0" }), "3.0.0");
});

test("a requested version must be above everything uploaded", () => {
  assert.equal(nextVersion({ existing: ["3.0.2"], project: "3.0.0", requested: "3.1" }), "3.1.0");
  assert.throws(() => nextVersion({ existing: ["3.0.2"], project: "3.0.0", requested: "3.0.2" }), /must be higher/);
  assert.throws(() => nextVersion({ existing: ["3.0.2"], project: "3.0.0", requested: "3.0.1" }), /must be higher/);
  assert.throws(() => nextVersion({ existing: [], project: "3.0.0", requested: "next" }), /not a version/);
});

test("the build number is one above every build, dotted ones included", () => {
  assert.equal(nextBuild({ existing: ["23.1", "41.2", "40"], project: "22" }), 42);
  assert.equal(nextBuild({ existing: [], project: "22" }), 23);
});
