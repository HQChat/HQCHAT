import assert from "node:assert/strict";
import { test } from "node:test";
import { assess, createAlerter, type Thresholds, thresholdsFromEnv } from "../../src/health-monitor";

const T: Thresholds = {
  loopWarnMs: 100,
  loopCritMs: 500,
  rssWarnMB: 700,
  rssCritMB: 900,
  handlesWarn: 10,
  handlesCrit: 20,
};
const calm = { eventLoopLagP99Ms: 5, rssMB: 100, activeHandles: 2 };

test("a calm process is ok", () => {
  assert.deepEqual(assess(calm, T), { status: "ok", tripped: [] });
});

test("each crossed threshold is named, and the worst status wins", () => {
  const a = assess({ eventLoopLagP99Ms: 600, rssMB: 750, activeHandles: 2 }, T);
  assert.equal(a.status, "crit");
  assert.deepEqual(a.tripped, ["event-loop p99 ms 600 >= 500", "rss MB 750 >= 700"]);
  assert.equal(assess({ ...calm, activeHandles: 12 }, T).status, "warn");
});

test("thresholds default when unset and read HEALTH_* overrides", () => {
  const saved = process.env.HEALTH_RSS_WARN_MB;
  process.env.HEALTH_RSS_WARN_MB = "123";
  try {
    const t = thresholdsFromEnv();
    assert.equal(t.rssWarnMB, 123);
    assert.equal(t.loopWarnMs, 100);
  } finally {
    if (saved === undefined) delete process.env.HEALTH_RSS_WARN_MB;
    else process.env.HEALTH_RSS_WARN_MB = saved;
  }
});

test("a sustained warning is reported once per cooldown", () => {
  let now = 0;
  const alert = createAlerter({ cooldownMs: 1000, now: () => now });
  const warn = { status: "warn" as const, tripped: ["rss MB 750 >= 700"] };
  assert.equal(alert(warn), "health WARN: rss MB 750 >= 700");
  now = 500;
  assert.equal(alert(warn), null);
  now = 1000;
  assert.match(alert(warn) ?? "", /WARN/);
});

test("escalating to crit is reported inside the cooldown", () => {
  let now = 0;
  const alert = createAlerter({ cooldownMs: 1000, now: () => now });
  alert({ status: "warn", tripped: ["a"] });
  now = 10;
  assert.equal(alert({ status: "crit", tripped: ["b"] }), "health CRIT: b");
  now = 20;
  assert.equal(alert({ status: "crit", tripped: ["b"] }), null);
});

test("recovering resets, so the next degradation is reported", () => {
  let now = 0;
  const alert = createAlerter({ cooldownMs: 1000, now: () => now });
  alert({ status: "crit", tripped: ["x"] });
  assert.equal(alert({ status: "ok", tripped: [] }), null);
  now = 5;
  assert.match(alert({ status: "crit", tripped: ["x"] }) ?? "", /CRIT/);
});
