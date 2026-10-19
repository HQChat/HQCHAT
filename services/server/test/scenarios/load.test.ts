import assert from "node:assert/strict";
import { test } from "node:test";
import type { Client } from "../reference/client";
import { friends, stackUp } from "./stack";

/**
 * Fan-out under concurrency. The report (latency percentiles) is the
 * deliverable; the assertions are correctness (every message arrives, intact)
 * and a loose ceiling that catches unbounded queueing, not slowness.
 *
 *   LOAD_PAIRS=10 LOAD_MESSAGES=20 npm run test:load
 */

const PAIRS = Number(process.env.LOAD_PAIRS || 10);
const PER_PAIR = Number(process.env.LOAD_MESSAGES || 20);

interface Stats {
  p50: number;
  p95: number;
  p99: number;
  max: number;
  n: number;
}

function percentiles(samples: number[]): Stats {
  const s = [...samples].sort((a, b) => a - b);
  const at = (p: number) => s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))] ?? 0;
  return { p50: at(50), p95: at(95), p99: at(99), max: s[s.length - 1] ?? 0, n: s.length };
}

const ms = (n: number) => `${n.toFixed(1)}ms`;

function report(title: string, s: Stats): void {
  console.log(`  ${title}: n=${s.n} p50=${ms(s.p50)} p95=${ms(s.p95)} p99=${ms(s.p99)} max=${ms(s.max)}`);
}

async function roundTrip(from: Client, to: Client, text: string): Promise<number> {
  const t0 = performance.now();
  await from.send(to.id, text);
  const got = await to.next(from.id);
  assert.equal(got.text, text);
  return performance.now() - t0;
}

test("fan-out latency under concurrency", async (t) => {
  if (!(await stackUp(t))) return;
  const pairs = [];
  for (let i = 0; i < PAIRS; i++) pairs.push(await friends());

  const solo: number[] = [];
  const first = pairs[0]!;
  for (let i = 0; i < PER_PAIR; i++) {
    solo.push(await roundTrip(first.a, first.b, `solo-a${i}`));
    solo.push(await roundTrip(first.b, first.a, `solo-b${i}`));
  }
  const soloStats = percentiles(solo);
  report("one conversation", soloStats);

  const concurrent: number[] = [];
  const started = Date.now();
  await Promise.all(
    pairs.map(async ({ a, b }, p) => {
      for (let i = 0; i < PER_PAIR; i++) {
        concurrent.push(await roundTrip(a, b, `p${p}-a${i}`));
        concurrent.push(await roundTrip(b, a, `p${p}-b${i}`));
      }
    }),
  );
  const stats = percentiles(concurrent);
  report(`${PAIRS} conversations at once`, stats);
  console.log(`  throughput: ${concurrent.length} messages in ${ms(Date.now() - started)}`);
  assert.equal(concurrent.length, PAIRS * PER_PAIR * 2);
  const ceiling = Math.max(soloStats.p99 * 30, 5_000);
  assert.ok(stats.p99 < ceiling, `p99 ${ms(stats.p99)} exceeds ${ms(ceiling)}`);
});

test("a client that never reads does not stall another conversation", async (t) => {
  if (!(await stackUp(t))) return;
  const slow = await friends();
  const fast = await friends();
  for (let i = 0; i < 50; i++) await slow.a.send(slow.b.id, `unread-${i}`);
  const samples: number[] = [];
  for (let i = 0; i < 20; i++) samples.push(await roundTrip(fast.a, fast.b, `fast-${i}`));
  const s = percentiles(samples);
  report("an unrelated conversation with 50 messages queued elsewhere", s);
  assert.ok(s.p99 < 5_000, `p99 ${ms(s.p99)}`);
});
