/**
 * The hourly report: at the top of every UTC hour (or every SIM_REPORT_MS, for
 * a local run), each sim's window rolls up into one `sim_reports` row, plus an
 * `all` row for the fleet. A row that cannot be written waits for the next
 * hour; the role may only insert, so a row once written stays as it was.
 */

import { logger } from "../common/logger";
import type { Sim } from "./sim";
import { type Metrics, merge, summarise } from "./stats";

export interface Row {
  hour: Date;
  sim: string;
  metrics: Metrics;
}

/** Rows kept for a later attempt while the database is unreachable: a day's worth. */
const MAX_PENDING_ROWS = 24 * 12;

/** Rolls every sim's window into its row and the fleet's `all` row. */
export function rows(sims: readonly Sim[], hour: Date): Row[] {
  const windows = sims.map((s) => ({ handle: s.handle, ...s.roll() }));
  const out: Row[] = windows.map((w) => ({
    hour,
    sim: w.handle,
    metrics: summarise(w.raw, w.windowMs, w.connectedMs, w.presentMs),
  }));
  const sum = (f: (w: (typeof windows)[number]) => number) => windows.reduce((n, w) => n + f(w), 0);
  out.push({
    hour,
    sim: "all",
    metrics: summarise(
      merge(windows.map((w) => w.raw)),
      Math.max(0, ...windows.map((w) => w.windowMs)),
      sum((w) => w.connectedMs),
      sum((w) => w.presentMs),
    ),
  });
  return out;
}

/** The start of the window that ends at `at`, on the `periodMs` grid. */
export function windowStart(at: number, periodMs: number): Date {
  return new Date(Math.floor(at / periodMs) * periodMs - periodMs);
}

export async function insertRows(
  query: (text: string, params: unknown[]) => Promise<unknown>,
  batch: readonly Row[],
): Promise<void> {
  for (const r of batch) {
    await query("INSERT INTO sim_reports (hour, sim, metrics) VALUES ($1, $2, $3) ON CONFLICT (hour, sim) DO NOTHING", [
      r.hour,
      r.sim,
      JSON.stringify(r.metrics),
    ]);
  }
}

export class Reporter {
  private pending: Row[] = [];

  constructor(
    private readonly sims: readonly Sim[],
    private readonly write: (rows: readonly Row[]) => Promise<void>,
    private readonly periodMs = 3_600_000,
    private readonly now: () => number = Date.now,
  ) {}

  start(): void {
    const wait = this.periodMs - (this.now() % this.periodMs);
    setTimeout(() => {
      void this.report();
      setInterval(() => void this.report(), this.periodMs);
    }, wait);
  }

  async report(): Promise<void> {
    const fresh = rows(this.sims, windowStart(this.now() + 1_000, this.periodMs));
    const all = fresh.find((r) => r.sim === "all")?.metrics;
    if (all) {
      const c = all.counts;
      logger.info(
        `[sim] window: ${c.pingsSent ?? 0} pings, ${c.echoesBack ?? 0} echoed, ${c.lost ?? 0} lost, ` +
          `${c.corrupted ?? 0} corrupted, ${c.fromReal ?? 0} from real users, uptime ${all.uptimePct}%`,
      );
    }
    const batch = [...this.pending, ...fresh];
    try {
      await this.write(batch);
      this.pending = [];
    } catch (e) {
      this.pending = batch.slice(-MAX_PENDING_ROWS);
      logger.error(
        `[sim] could not write ${batch.length} report rows (kept for the next hour): ${(e as Error).message}`,
      );
    }
  }
}
