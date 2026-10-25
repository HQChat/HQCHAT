// The sim node's behaviour (src/sim/sim.ts) and its hourly roll-up
// (src/sim/report.ts), on a fake client, a fake clock and a seeded RNG.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { CoreEffect, CoreFriend, CoreInvite, CoreMessage } from "../../src/common/core";
import { rows, windowStart } from "../../src/sim/report";
import {
  ECHO_CAP_PER_MIN,
  type Env,
  type Fleet,
  LOST_MS,
  REAL_REINVITE_EVERY_MS,
  REINVITE_AFTER_MS,
  RealUsers,
  reasonKey,
  Sim,
  type SimClient,
} from "../../src/sim/sim";

const HOUR = 3_600_000;

/** mulberry32: the same sequence on every run. */
function seeded(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function setup(opts: { sims?: string[]; friends?: Partial<CoreFriend>[]; rng?: () => number } = {}) {
  let clock = 1_000_000;
  const timers: { at: number; fn: () => void }[] = [];
  const env: Env = {
    rng: opts.rng ?? seeded(7),
    now: () => clock,
    later: (ms, fn) => timers.push({ at: clock + ms, fn }),
  };
  const simIds = opts.sims ?? ["s1", "s2", "s3", "s4"];
  const fleet: Fleet = {
    sims: new Map(simIds.map((id, i) => [id, `echo_0${i + 1}`])),
    botId: "bot",
    realUsers: new RealUsers(null),
  };
  const sent: { peer: string; text: string; id: string }[] = [];
  const calls: string[] = [];
  let invites: CoreInvite[] = [];
  let onMessage: (m: CoreMessage) => void = () => {};
  let onEffect: (e: CoreEffect) => void = () => {};
  const friends = (opts.friends ?? []).map((f) => ({ online: true, ...f }) as CoreFriend);
  const record = (what: string) => {
    calls.push(what);
    return [];
  };
  const client: SimClient = {
    start: () => {},
    setReachable: (r) => void calls.push(`reachable:${r}`),
    onMessage: (fn) => {
      onMessage = fn;
    },
    onEffect: (fn) => {
      onEffect = fn;
    },
    run: (command) => void command(),
    send: (peer, text) => {
      const id = `m${sent.length + 1}`;
      sent.push({ peer, text, id });
      return id;
    },
    engine: {
      friends: () => friends,
      invites: () => invites,
      sentInvites: () => [],
      invite: (u) => record(`invite:${u}`),
      accept: (p) => record(`accept:${p}`),
      cancel: (p) => record(`cancel:${p}`),
      remove: (p) => record(`remove:${p}`),
      retry: (m) => record(`retry:${m}`),
      setUsername: (u) => record(`username:${u}`),
    },
  };
  const sim = new Sim(client, "echo_01", "hqn", fleet, env);
  return {
    sim,
    fleet,
    sent,
    calls,
    timers,
    advance: (ms: number) => {
      clock += ms;
    },
    message: (peer: string, text: string) =>
      onMessage({ msgId: `in${Math.random()}`, peer, outgoing: false, text, at: clock }),
    effect: (e: Partial<CoreEffect>) => onEffect(e as CoreEffect),
    setInvites: (list: CoreInvite[]) => {
      invites = list;
    },
    counts: () => Object.fromEntries(sim.tally.take().counts),
  };
}

test("anything a real user or another sim sends comes back exactly", () => {
  const t = setup();
  const text = "héllo\n  😀 <b>&amp;</b>  ";
  t.message("realuser", text);
  t.message("s2", "ping echo_02·4·0badf00d");
  assert.deepEqual(
    t.sent.map(({ peer, text }) => ({ peer, text })),
    [
      { peer: "realuser", text },
      { peer: "s2", text: "ping echo_02·4·0badf00d" },
    ],
  );
  const c = t.counts();
  assert.equal(c.fromReal, 1);
  assert.equal(c.fromSims, 1);
});

test("a sim's own ping coming back is timed and never echoed, and a second copy is a duplicate", () => {
  const t = setup({ friends: [{ id: "s2" }] });
  t.sim.ping();
  assert.equal(t.sent.length, 1);
  const ping = t.sent[0]!;
  assert.equal(ping.peer, "s2");
  assert.match(ping.text, /^ping echo_01·1·[0-9a-f]{8}$/);
  t.advance(250);
  t.message("s2", ping.text);
  t.message("s2", ping.text);
  assert.equal(t.sent.length, 1, "nothing goes back");
  const raw = t.sim.tally.take();
  assert.equal(raw.counts.get("echoesBack"), 1);
  assert.equal(raw.counts.get("duplicates"), 1);
  assert.deepEqual(raw.samples.get("rtt.hqn.online"), [250]);
});

test("an own ping with other text is corrupted, and the helper bot is ignored", () => {
  const t = setup({ friends: [{ id: "s2" }] });
  t.sim.ping();
  t.message("s2", t.sent[0]!.text.replace(/·[0-9a-f]{8}$/, "·deadbeef"));
  t.message("bot", "welcome to hqchat");
  assert.equal(t.sent.length, 1);
  const c = t.counts();
  assert.equal(c.corrupted, 1);
  assert.equal(c.fromBot, 1);
});

test("a ping without its echo is lost after five minutes, and a late echo is still never echoed", () => {
  const t = setup({ friends: [{ id: "s2", online: false }] });
  t.sim.ping();
  t.advance(LOST_MS + 1);
  t.sim.sweep();
  t.message("s2", t.sent[0]!.text);
  assert.equal(t.sent.length, 1);
  const raw = t.sim.tally.take();
  assert.equal(raw.counts.get("lost"), 1);
  assert.equal(raw.counts.get("late"), 1);
  assert.equal(raw.counts.get("lateAfterLost"), 1);
  assert.deepEqual(raw.samples.get("rtt.hqn.offline"), [LOST_MS + 1]);
});

test("echoes to one peer stop at the cap within a minute, and resume after it", () => {
  const t = setup();
  for (let i = 0; i < ECHO_CAP_PER_MIN + 5; i++) t.message("loopbot", `x${i}`);
  assert.equal(t.sent.length, ECHO_CAP_PER_MIN);
  assert.equal(t.counts().echoesCapped, 5);
  t.advance(60_000);
  t.message("loopbot", "again");
  assert.equal(t.sent.length, ECHO_CAP_PER_MIN + 1);
});

test("about half the invites are accepted, the rest declined, and declined real users are remembered", () => {
  const t = setup();
  for (let i = 0; i < 1000; i++) {
    const invite = { id: `u${i}`, username: `user${i}` };
    t.setInvites([invite]);
    t.sim.decide(invite);
  }
  const c = t.counts();
  const accepted = c["accepted.real"] ?? 0;
  assert.equal(accepted + (c["declined.real"] ?? 0), 1000);
  assert.ok(accepted > 450 && accepted < 550, `${accepted} of 1000 accepted`);
  assert.equal(t.calls.filter((x) => x.startsWith("accept:")).length, accepted);
  assert.equal(t.calls.filter((x) => x.startsWith("cancel:")).length, 1000 - accepted);
});

test("a withdrawn invite is not answered", () => {
  const t = setup();
  t.setInvites([]);
  t.sim.decide({ id: "u1", username: "user1" });
  assert.deepEqual(t.calls, []);
  assert.equal(t.counts().invitesWithdrawn, 1);
});

test("an invite is decided once, after a delay", () => {
  const t = setup();
  t.setInvites([{ id: "s2", username: "echo_02" }]);
  t.effect({ kind: "invitesChanged" });
  t.effect({ kind: "invitesChanged" });
  assert.equal(t.timers.filter((x) => x.at > 1_000_000 + 9_999).length, 1);
  assert.equal(t.counts()["invitesFrom.sims"], 1);
});

test("sims are invited a few at a time, and not again before the cooldown", () => {
  const t = setup({ rng: () => 0.9 });
  const invited = () => t.calls.filter((x) => x.startsWith("invite:")).length;
  t.sim.social();
  assert.equal(invited(), 2);
  t.sim.social();
  assert.equal(invited(), 3, "only the one not yet invited");
  t.sim.social();
  assert.equal(invited(), 3);
  t.advance(REINVITE_AFTER_MS);
  t.sim.social();
  assert.equal(invited(), 5);
  assert.ok(!t.calls.includes("invite:echo_01"), "a sim never invites itself");
});

test("a declined real user is invited back by another sim, after an hour, once a week", () => {
  const users = new RealUsers(null);
  const always = () => 0;
  users.declined("u1", "alice", "echo_01", 0);
  assert.equal(
    users.pick("echo_02", HOUR - 1, always, () => false),
    null,
    "not within the hour",
  );
  assert.equal(
    users.pick("echo_01", HOUR, always, () => false),
    null,
    "not by the sim that declined",
  );
  assert.equal(
    users.pick("echo_02", HOUR, always, (id) => id === "u1"),
    null,
    "not when already a friend",
  );
  assert.deepEqual(
    users.pick("echo_02", HOUR, always, () => false),
    { id: "u1", username: "alice" },
  );
  assert.equal(
    users.pick("echo_03", 2 * HOUR, always, () => false),
    null,
    "once a week",
  );
  assert.ok(users.pick("echo_03", HOUR + REAL_REINVITE_EVERY_MS, always, () => false));
});

test("delivery states are timed once each, and a failed message is retried, then given up", () => {
  const t = setup();
  t.message("realuser", "hi");
  t.advance(120);
  t.effect({ kind: "messageStatus", msgId: "m1", state: "sent" });
  t.effect({ kind: "messageStatus", msgId: "m1", state: "sent" });
  t.advance(80);
  t.effect({ kind: "messageStatus", msgId: "m1", state: "delivered" });
  t.message("realuser", "again");
  for (let i = 0; i < 4; i++) {
    t.effect({ kind: "messageStatus", msgId: "m2", state: "failed" });
    for (const x of t.timers.splice(0)) x.fn();
  }
  const raw = t.sim.tally.take();
  assert.deepEqual(raw.samples.get("sent.echoReal"), [120]);
  assert.deepEqual(raw.samples.get("delivered.echoReal"), [200]);
  assert.equal(raw.counts.get("delivery.echoReal.failed"), 4);
  assert.equal(raw.counts.get("delivery.echoReal.gaveUp"), 1);
  assert.equal(t.calls.filter((x) => x === "retry:m2").length, 3);
});

test("the hourly roll-up sums the fleet and measures uptime without the time away", () => {
  const a = setup();
  const b = setup();
  for (const t of [a, b]) {
    t.effect({ kind: "connection", state: "connected" });
    t.message("realuser", "hi");
  }
  a.advance(HOUR / 2);
  a.effect({ kind: "connection", state: "offline" });
  a.advance(HOUR / 2);
  b.advance(HOUR);
  const out = rows([a.sim, b.sim], new Date(0));
  assert.equal(out.length, 3);
  const all = out.find((r) => r.sim === "all")!.metrics;
  assert.equal(all.counts.fromReal, 2);
  assert.equal(all.counts.realUsers, 2);
  assert.equal(all.counts.drops, 1);
  assert.equal(all.counts.connects, 2);
  assert.equal(all.uptimePct, 75);
  assert.equal(out[0]!.metrics.uptimePct, 50);
  assert.equal(out[0]!.metrics.windowMs, HOUR);
  assert.deepEqual(a.calls, ["username:echo_01"], "the handle is claimed on the first connect");
  assert.equal(windowStart(Date.UTC(2026, 9, 25, 14, 0, 0, 900), HOUR).toISOString(), "2026-10-25T13:00:00.000Z");
});

test("a core drop reason becomes a counter key with no ids or values in it", () => {
  assert.equal(reasonKey("own frame"), "own_frame");
  assert.equal(reasonKey('could not seal for 3fa9c2…: Crypto("bad")'), "could_not_seal_for");
  assert.equal(reasonKey("publish on cv/3fa9…"), "publish_on");
  assert.equal(reasonKey("simultaneous init: keeping ours (lower id)"), "simultaneous_init");
  assert.equal(reasonKey(undefined), "other");
  const t = setup();
  t.effect({ kind: "dropped", reason: "own frame" });
  assert.equal(t.counts()["dropped.own_frame"], 1);
});
