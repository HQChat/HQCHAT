import * as fs from "node:fs";

/**
 * How many AI replies the bot gives. Every new account is befriended to the
 * bot, so accounts are free to make: the per-peer limits keep one person from
 * spending the budget, and the global one bounds the bill however many
 * accounts ask.
 */
export interface QuotaLimits {
  perMinute: number;
  perDay: number;
  globalPerDay: number;
}

export type QuotaRefusal = "minute" | "day" | "global";

interface Counts {
  /** UTC day the counts are for, YYYY-MM-DD. */
  day: string;
  global: number;
  peers: Record<string, number>;
}

const MINUTE_MS = 60_000;

/**
 * Daily counts persist to `file` (ids and numbers, no text), so a restart does
 * not hand out a second day's budget. The per-minute window is kept in memory.
 */
export class Quota {
  private counts: Counts;
  private readonly recent = new Map<string, number[]>();

  constructor(
    private readonly file: string,
    private readonly limits: QuotaLimits,
  ) {
    this.counts = fs.existsSync(file) ? (JSON.parse(fs.readFileSync(file, "utf8")) as Counts) : empty("");
  }

  /** Counts one reply for `peer`, or says which limit refuses it (and counts nothing). */
  take(peer: string, now: number): QuotaRefusal | null {
    const day = new Date(now).toISOString().slice(0, 10);
    if (this.counts.day !== day) this.counts = empty(day);
    const recent = (this.recent.get(peer) ?? []).filter((t) => now - t < MINUTE_MS);
    if (this.counts.global >= this.limits.globalPerDay) return "global";
    if ((this.counts.peers[peer] ?? 0) >= this.limits.perDay) return "day";
    if (recent.length >= this.limits.perMinute) return "minute";
    recent.push(now);
    this.recent.set(peer, recent);
    this.counts.global += 1;
    this.counts.peers[peer] = (this.counts.peers[peer] ?? 0) + 1;
    fs.writeFileSync(this.file, JSON.stringify(this.counts), { mode: 0o600 });
    return null;
  }

  /** What `peer` has left today. */
  left(peer: string, now: number): number {
    const day = new Date(now).toISOString().slice(0, 10);
    if (this.counts.day !== day) return this.limits.perDay;
    return Math.max(0, this.limits.perDay - (this.counts.peers[peer] ?? 0));
  }
}

function empty(day: string): Counts {
  return { day, global: 0, peers: {} };
}
