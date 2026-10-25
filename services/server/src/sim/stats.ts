/**
 * Counters and latency samples for one sim over one report window. Only
 * counts and milliseconds: no message text, no peer ids.
 */

export interface Percentiles {
  n: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
}

export function percentiles(samples: readonly number[]): Percentiles {
  const s = [...samples].sort((a, b) => a - b);
  const at = (p: number) => s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))] ?? 0;
  return { n: s.length, p50: at(50), p95: at(95), p99: at(99), max: s[s.length - 1] ?? 0 };
}

/** What a window rolls up to: the row's `metrics`. */
export interface Metrics {
  /** Window length, ms. */
  windowMs: number;
  counts: Record<string, number>;
  /** Latencies by bucket (`rtt.hqn.online`, `delivered.echoReal`, `reconnect`, …). */
  ms: Record<string, Percentiles>;
  /** Share of the window connected, leaving out the time the sim chose to be away; null when it was away throughout. */
  uptimePct: number | null;
}

export class Tally {
  private counts = new Map<string, number>();
  private samples = new Map<string, number[]>();

  count(name: string, n = 1): void {
    this.counts.set(name, (this.counts.get(name) ?? 0) + n);
  }

  sample(bucket: string, ms: number): void {
    const list = this.samples.get(bucket);
    if (list) list.push(ms);
    else this.samples.set(bucket, [ms]);
  }

  /** The raw window, for merging the fleet's `all` row before it is summarised. */
  take(): { counts: Map<string, number>; samples: Map<string, number[]> } {
    const out = { counts: this.counts, samples: this.samples };
    this.counts = new Map();
    this.samples = new Map();
    return out;
  }
}

/** Sums counts and pools samples across sims. */
export function merge(parts: { counts: Map<string, number>; samples: Map<string, number[]> }[]): {
  counts: Map<string, number>;
  samples: Map<string, number[]>;
} {
  const counts = new Map<string, number>();
  const samples = new Map<string, number[]>();
  for (const p of parts) {
    for (const [k, v] of p.counts) counts.set(k, (counts.get(k) ?? 0) + v);
    for (const [k, v] of p.samples) samples.set(k, [...(samples.get(k) ?? []), ...v]);
  }
  return { counts, samples };
}

export function summarise(
  raw: { counts: Map<string, number>; samples: Map<string, number[]> },
  windowMs: number,
  connectedMs: number,
  presentMs: number,
): Metrics {
  const sorted = <T>(m: Map<string, T>) => [...m.entries()].sort(([a], [b]) => a.localeCompare(b));
  return {
    windowMs,
    counts: Object.fromEntries(sorted(raw.counts)),
    ms: Object.fromEntries(sorted(raw.samples).map(([k, v]) => [k, percentiles(v)])),
    uptimePct: presentMs > 0 ? Math.round((Math.min(connectedMs, presentMs) / presentMs) * 10_000) / 100 : null,
  };
}
