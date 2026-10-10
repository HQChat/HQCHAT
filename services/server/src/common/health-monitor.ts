import { monitorEventLoopDelay } from "node:perf_hooks";
import { logger } from "./logger";
import { Sentry, sentryEnabled } from "./observability";

export type HealthStatus = "ok" | "warn" | "crit";

/** One sample of the process vitals. */
export interface Vitals {
  eventLoopLagP99Ms: number;
  rssMB: number;
  activeHandles: number;
}

export interface Thresholds {
  loopWarnMs: number;
  loopCritMs: number;
  rssWarnMB: number;
  rssCritMB: number;
  handlesWarn: number;
  handlesCrit: number;
}

export interface Assessment {
  status: HealthStatus;
  tripped: string[];
}

function envNum(name: string, def: number): number {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : def;
}

/** Defaults, each overridable as HEALTH_<NAME>. */
export function thresholdsFromEnv(): Thresholds {
  return {
    loopWarnMs: envNum("HEALTH_LOOP_WARN_MS", 100),
    loopCritMs: envNum("HEALTH_LOOP_CRIT_MS", 500),
    rssWarnMB: envNum("HEALTH_RSS_WARN_MB", 700),
    rssCritMB: envNum("HEALTH_RSS_CRIT_MB", 900),
    handlesWarn: envNum("HEALTH_HANDLES_WARN", 6000),
    handlesCrit: envNum("HEALTH_HANDLES_CRIT", 12000),
  };
}

/** Which thresholds a sample crosses, and the worst resulting status. */
export function assess(v: Vitals, t: Thresholds): Assessment {
  const tripped: string[] = [];
  let status: HealthStatus = "ok";
  const check = (value: number, warn: number, crit: number, label: string) => {
    if (value >= crit) {
      tripped.push(`${label} ${Math.round(value)} >= ${crit}`);
      status = "crit";
    } else if (value >= warn) {
      tripped.push(`${label} ${Math.round(value)} >= ${warn}`);
      if (status === "ok") status = "warn";
    }
  };
  check(v.eventLoopLagP99Ms, t.loopWarnMs, t.loopCritMs, "event-loop p99 ms");
  check(v.rssMB, t.rssWarnMB, t.rssCritMB, "rss MB");
  check(v.activeHandles, t.handlesWarn, t.handlesCrit, "active handles");
  return { status, tripped };
}

/**
 * Turns assessments into alert lines: a degraded state is reported at most once
 * per `cooldownMs`, except that reaching crit is reported immediately.
 */
export function createAlerter(opts: { cooldownMs: number; now?: () => number }) {
  const now = opts.now ?? Date.now;
  let lastAt: number | null = null;
  let lastStatus: HealthStatus = "ok";
  return (a: Assessment): string | null => {
    if (a.status === "ok") {
      lastStatus = "ok";
      return null;
    }
    const t = now();
    const escalated = a.status === "crit" && lastStatus !== "crit";
    if (!escalated && lastAt !== null && t - lastAt < opts.cooldownMs) return null;
    lastAt = t;
    lastStatus = a.status;
    return `health ${a.status.toUpperCase()}: ${a.tripped.join("; ")}`;
  };
}

/**
 * Samples event-loop lag, RSS and active handles every HEALTH_SAMPLE_MS and
 * logs a warning or error before the process runs out of headroom.
 */
export function startHealthMonitor(): void {
  const thresholds = thresholdsFromEnv();
  const alert = createAlerter({ cooldownMs: envNum("HEALTH_ALERT_COOLDOWN_MS", 60_000) });
  const hist = monitorEventLoopDelay({ resolution: 10 });
  hist.enable();
  setInterval(
    () => {
      const vitals: Vitals = {
        eventLoopLagP99Ms: hist.percentile(99) / 1e6,
        rssMB: process.memoryUsage().rss / (1024 * 1024),
        activeHandles: process.getActiveResourcesInfo().length,
      };
      hist.reset();
      const a = assess(vitals, thresholds);
      if (sentryEnabled()) Sentry.setContext("vitals", { ...vitals, status: a.status });
      const line = alert(a);
      if (line === null) return;
      if (a.status === "crit") logger.error(line);
      else logger.warn(line);
    },
    envNum("HEALTH_SAMPLE_MS", 5000),
  ).unref();
}
