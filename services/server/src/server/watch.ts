import { logger } from "../common/logger";
import { ping, sweepExpired } from "./db/pg";
import { emqxApi, emqxApiConfigured } from "./emqx";

/**
 * Watches what the Node services cannot see from inside: EMQX's authentication
 * and authorization links, the settings the conversation ACL depends on, and
 * Postgres. Failures are escalated to the log (and so Sentry) on transition and
 * re-alerted while they last; expired rows are swept on their own interval.
 */

const INTERVAL_MS = Number(process.env.BROKER_WATCH_INTERVAL_MS || 30_000);
const REALERT_MS = Number(process.env.BROKER_WATCH_REALERT_MS || 30 * 60_000);
const SWEEP_MS = Number(process.env.PG_SWEEP_INTERVAL_MS || 5 * 60_000);

/** One health check result. */
export interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

async function api<T>(path: string): Promise<T> {
  const res = await emqxApi("GET", path);
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return (await res.json()) as T;
}

/** Healthy when enabled and, for connector-backed sources, connected. */
export function linkOk(x: { enable?: boolean; status?: string }): boolean {
  if (x.enable === false) return false;
  return x.status === undefined || x.status === "connected";
}

/** EMQX's per-node errors, flattened into one detail suffix. */
export function nodeErrors(x: { node_error?: unknown[] }): string {
  const errs = x.node_error || [];
  if (!errs.length) return "";
  return ` — ${errs
    .map((e) => (typeof e === "string" ? e : JSON.stringify(e)))
    .join("; ")
    .slice(0, 300)}`;
}

async function probe(name: string, fn: () => Promise<{ ok: boolean; detail: string }>): Promise<Check> {
  try {
    return { name, ...(await fn()) };
  } catch (e) {
    return { name, ok: false, detail: (e as Error).message };
  }
}

type Link = {
  mechanism?: string;
  backend?: string;
  type?: string;
  enable?: boolean;
  status?: string;
  node_error?: unknown[];
};

async function nodeChecks(): Promise<Check[]> {
  type Node = { node: string; node_status: string; connections: number };
  return (await api<Node[]>("nodes")).map((n) => ({
    name: `emqx.node.${n.node}`,
    ok: n.node_status === "running",
    detail: `${n.node_status}, ${n.connections} connections`,
  }));
}

function linkCheck(name: string, link: Link): Check {
  return { name, ok: linkOk(link), detail: `status=${link.status ?? "n/a"} enable=${link.enable}${nodeErrors(link)}` };
}

async function authnChecks(): Promise<Check[]> {
  const authn = await api<Link[]>("authentication");
  const checks = authn.map((a) =>
    linkCheck(`emqx.authn.${[a.mechanism, a.backend].filter(Boolean).join(":") || "authn"}`, a),
  );
  if (!authn.length) {
    checks.unshift({
      name: "emqx.authn",
      ok: false,
      detail: "no authenticator configured — the broker is admitting everyone",
    });
  }
  return checks;
}

async function authzChecks(): Promise<Check[]> {
  const { sources = [] } = await api<{ sources?: Link[] }>("authorization/sources");
  const checks = sources.map((s) => linkCheck(`emqx.authz.${s.type || "source"}`, s));
  if (!sources.length) {
    checks.unshift({
      name: "emqx.authz",
      ok: false,
      detail: "no authorization source configured — the topic ACL is not enforced",
    });
  } else if (!sources.some((s) => s.type === "file" && s.enable !== false)) {
    checks.unshift({ name: "emqx.authz", ok: false, detail: "the static file ACL is not loaded" });
  }
  checks.push(
    await probe("emqx.authz.no_match", async () => {
      const { no_match } = await api<{ no_match?: string }>("authorization/settings");
      return { ok: no_match === "deny", detail: `no_match=${no_match ?? "n/a"}` };
    }),
  );
  return checks;
}

function wildcardCheck(): Promise<Check> {
  return probe("emqx.wildcard_subscription", async () => {
    const zone = await api<{ mqtt?: { wildcard_subscription?: boolean } }>("configs/global_zone");
    const on = zone.mqtt?.wildcard_subscription;
    return {
      ok: on === false,
      detail: on === false ? "off for clients" : `wildcard_subscription=${on} — any client can read every conversation`,
    };
  });
}

/** Nodes, authentication, the file ACL, `no_match = deny` and client wildcards off. */
export async function checkEmqx(): Promise<Check[]> {
  return [...(await nodeChecks()), ...(await authnChecks()), ...(await authzChecks()), await wildcardCheck()];
}

export async function checkPostgres(): Promise<Check> {
  const t0 = Date.now();
  try {
    return { name: "postgres.ping", ok: await ping(), detail: `SELECT 1 in ${Date.now() - t0}ms` };
  } catch (e) {
    return { name: "postgres.ping", ok: false, detail: (e as Error).message };
  }
}

/** Deletes expired rows; never throws. */
export async function sweep(): Promise<void> {
  try {
    const removed = await sweepExpired();
    const total = Object.values(removed).reduce((a, b) => a + b, 0);
    if (total) logger.debug(`[watch] swept ${total} expired rows: ${JSON.stringify(removed)}`);
  } catch (e) {
    logger.warn(`[watch] sweep failed: ${(e as Error).message}`);
  }
}

export interface Escalator {
  escalate(c: Check): void;
  state: Map<string, { ok: boolean; since: number; lastAlertAt: number }>;
}

export interface EscalatorSink {
  alert(message: string): void;
  recovered(message: string): void;
}

/**
 * Turns a stream of checks into alerts: once when a check starts failing, again
 * every `realertMs` while it keeps failing, and a recovery line when it passes.
 */
export function createEscalator(opts: { realertMs: number; now?: () => number; sink?: EscalatorSink }): Escalator {
  const now = opts.now ?? (() => Date.now());
  const sink = opts.sink ?? { alert: (m) => logger.error(m), recovered: (m) => logger.startup(m) };
  const state = new Map<string, { ok: boolean; since: number; lastAlertAt: number }>();

  function escalate(c: Check): void {
    const t = now();
    const prev = state.get(c.name);
    if (!c.ok) {
      const failingSince = prev && !prev.ok ? prev.since : t;
      if (!prev || prev.ok || t - prev.lastAlertAt >= opts.realertMs) {
        const forMs = t - failingSince;
        const forStr = forMs ? ` (unhealthy for ${Math.round(forMs / 60_000)}m)` : "";
        sink.alert(`[watch] ${c.name} unhealthy${forStr}: ${c.detail}`);
        state.set(c.name, { ok: false, since: failingSince, lastAlertAt: t });
      }
      return;
    }
    if (prev && !prev.ok) {
      sink.recovered(`[watch] ${c.name} recovered after ${Math.round((t - prev.since) / 60_000)}m: ${c.detail}`);
    }
    state.set(c.name, { ok: true, since: prev?.ok ? prev.since : t, lastAlertAt: 0 });
  }
  return { escalate, state };
}

const escalator = createEscalator({ realertMs: REALERT_MS });
let lastRun: { ts: number; checks: Check[] } = { ts: 0, checks: [] };

export function lastChecks(): Check[] {
  return lastRun.checks;
}

/** The latest result: how long ago it ran and which checks failed. */
export function watchStatus(): { lastRunAgoMs: number | null; unhealthy: string[] } {
  return {
    lastRunAgoMs: lastRun.ts ? Date.now() - lastRun.ts : null,
    unhealthy: lastRun.checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`),
  };
}

/** Runs every check once and escalates the results. */
export async function tick(): Promise<void> {
  const checks: Check[] = [await checkPostgres()];
  try {
    checks.push(...(await checkEmqx()));
  } catch (e) {
    checks.push({ name: "emqx.api", ok: false, detail: (e as Error).message });
  }
  for (const c of checks) escalator.escalate(c);
  lastRun = { ts: Date.now(), checks };
}

/** Starts the check and sweep intervals. */
export function startWatch(): void {
  if (!emqxApiConfigured()) logger.error("[watch] no EMQX API key configured; the broker cannot be checked");
  void tick();
  setInterval(() => void tick(), INTERVAL_MS).unref();
  void sweep();
  setInterval(() => void sweep(), SWEEP_MS).unref();
}
