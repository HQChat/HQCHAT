/**
 * Leveled logger. Console output is redacted (scrub.ts) and control characters
 * are escaped so a logged value cannot forge a line. info/warn/error leave a
 * Sentry breadcrumb; error and event also send a Sentry event, error being
 * throttled per message fingerprint. Sentry is reached through a sink that
 * observability.ts registers, so this module does not import it.
 */

import { redact, scrubDeep } from "./scrub";

/** C0, DEL, C1, U+2028 and U+2029. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the purpose
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;
const NAMED: Record<string, string> = { "\n": "\\n", "\r": "\\r", "\t": "\\t" };

/** Escapes control characters as `\n`, `\r`, `\t`, `\xNN` or `\uNNNN`. */
export function escapeControl(s: string): string {
  return s.replace(CONTROL_RE, (c) => {
    const named = NAMED[c];
    if (named) return named;
    const code = c.codePointAt(0)!;
    return code <= 0xff ? `\\x${code.toString(16).padStart(2, "0")}` : `\\u${code.toString(16).padStart(4, "0")}`;
  });
}

/** Escapes every string in a value, keys included. */
function escapeDeep(v: unknown, depth = 0): unknown {
  if (typeof v === "string") return escapeControl(v);
  if (depth > 8 || v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map((x) => escapeDeep(x, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(v)) out[escapeControl(k)] = escapeDeep(val, depth + 1);
  return out;
}

/**
 * The error with its message escaped and its V8 stack frames kept. Frames are
 * taken from after the `name: message` prefix, so a message cannot inject a
 * fake frame; a stack without that prefix loses its frames. Errors with
 * nothing to escape are returned unchanged.
 */
function safeError(e: Error): Error {
  const message = escapeControl(e.message);
  if (message === e.message) return e;
  const head = e.message ? `${e.name}: ${e.message}` : e.name;
  const stack = e.stack ?? "";
  const rest = stack.startsWith(head) ? stack.slice(head.length) : "";
  const frames = rest.split("\n").filter((l) => /^\s+at\s/.test(l));
  const copy = new Error(message);
  copy.name = escapeControl(e.name);
  copy.stack = [`${copy.name}: ${message}`, ...frames].join("\n");
  return copy;
}

function scrubArg(a: unknown): unknown {
  if (typeof a === "string") return escapeControl(redact(a));
  if (a instanceof Error) return safeError(a);
  return escapeDeep(scrubDeep(a));
}
function scrubArgs(args: unknown[]): unknown[] {
  return args.map(scrubArg);
}

export type LogLevel = "silent" | "error" | "warn" | "info" | "debug";

const ORDER: Record<LogLevel, number> = {
  silent: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4,
};

function resolveLevel(): LogLevel {
  const raw = (process.env.LOG_LEVEL || "").toLowerCase();
  if (raw in ORDER) return raw as LogLevel;
  return process.env.NODE_ENV === "production" ? "info" : "debug";
}

let currentLevel: LogLevel = resolveLevel();
export function setLogLevel(l: LogLevel) {
  currentLevel = l;
}
export function getLogLevel(): LogLevel {
  return currentLevel;
}
function enabled(l: Exclude<LogLevel, "silent">): boolean {
  return ORDER[currentLevel] >= ORDER[l];
}

/** Where breadcrumbs and events go once Sentry is initialised. */
export interface SentrySink {
  breadcrumb: (level: "info" | "warning" | "error", message: string) => void;
  captureError: (err: unknown, message?: string) => void;
  captureMessage: (message: string, level: "warning" | "error") => void;
}
let sink: SentrySink | null = null;
export function registerSentrySink(s: SentrySink) {
  sink = s;
}

function fmt(args: unknown[]): string {
  return args
    .map((a) =>
      typeof a === "string"
        ? a
        : a instanceof Error
          ? a.stack || a.message
          : (() => {
              try {
                return JSON.stringify(a);
              } catch {
                return String(a);
              }
            })(),
    )
    .join(" ");
}

/**
 * Sentry events from `error` are throttled per fingerprint: the first goes
 * through, then at most one per SENTRY_THROTTLE_MS (read per call, default 10
 * minutes) carrying the count suppressed meanwhile. The console is never
 * throttled.
 */
function throttleMs(): number {
  const raw = Number(process.env.SENTRY_THROTTLE_MS);
  return Number.isFinite(raw) && raw >= 0 ? raw : 10 * 60 * 1000;
}
const THROTTLE_MAX_KEYS = 500;

interface Seen {
  until: number;
  suppressed: number;
}
const seen = new Map<string, Seen>();

let clock: () => number = Date.now;
/** Replaces the throttle clock; no argument restores `Date.now`. */
export function setLoggerClock(fn?: () => number): void {
  clock = fn ?? Date.now;
}

/**
 * The message with ids, numbers and handles collapsed, so one failure about
 * different peers shares one throttle budget. Truncated first to bound the
 * regex work.
 */
export function fingerprint(message: string): string {
  return message
    .slice(0, 200)
    .replace(/\b[0-9a-f]{6,}\b/gi, "#")
    .replace(/\b\d+\b/g, "#")
    .replace(/@\S*/g, "@")
    .replace(/\s+/g, " ")
    .trim();
}

/** Whether this message may spend a Sentry event now, and what to append. */
function admit(message: string): { send: boolean; note: string } {
  const now = clock();
  const key = fingerprint(message);
  const prev = seen.get(key);

  if (prev && now < prev.until) {
    prev.suppressed++;
    return { send: false, note: "" };
  }

  if (seen.size >= THROTTLE_MAX_KEYS && !prev) {
    const oldest = seen.keys().next();
    if (!oldest.done) seen.delete(oldest.value);
  }
  const window = throttleMs();
  seen.set(key, { until: now + window, suppressed: 0 });

  const n = prev?.suppressed ?? 0;
  return {
    send: true,
    note: n > 0 ? ` [+${n} identical suppressed in the last ${Math.round(window / 60000)}m]` : "",
  };
}

/** Forgets every throttle window. */
export function resetSentryThrottle(): void {
  seen.clear();
  for (const b of batches.values()) if (b.timer) clearTimeout(b.timer);
  batches.clear();
}

/** How often a batched event may reach Sentry (SENTRY_BATCH_MS, read per call; default 10 minutes). */
function batchMs(): number {
  const raw = Number(process.env.SENTRY_BATCH_MS);
  return Number.isFinite(raw) && raw >= 0 ? raw : 10 * 60 * 1000;
}

interface Batch {
  until: number;
  held: number;
  timer: NodeJS.Timeout | null;
}
const batches = new Map<string, Batch>();

/** Sends the summary of what a batch held back, if anything, and opens a new window. */
function flushBatch(key: string): void {
  const b = batches.get(key);
  if (!b) return;
  if (b.timer) clearTimeout(b.timer);
  b.timer = null;
  if (b.held === 0) return;
  sink?.captureMessage(`${key}: ${b.held} more since the last alert`, "warning");
  b.held = 0;
  b.until = clock() + batchMs();
}

/** Sends every held-back batch summary now (tests, shutdown). */
export function flushBatchedEvents(): void {
  for (const key of [...batches.keys()]) flushBatch(key);
}

export const logger = {
  /** Per-message tracing; console only, shown at LOG_LEVEL=debug. */
  debug(...args: unknown[]) {
    if (enabled("debug")) console.log(...scrubArgs(args));
  },
  info(...args: unknown[]) {
    if (enabled("info")) console.log(...scrubArgs(args));
    sink?.breadcrumb("info", fmt(args));
  },
  warn(...args: unknown[]) {
    if (enabled("warn")) console.warn(...scrubArgs(args));
    const msg = fmt(args);
    sink?.breadcrumb("warning", msg);
  },
  /**
   * A failure: printed to stderr and sent to Sentry (throttled). Pass an Error
   * first for a stack. Expected, self-resolving conditions belong in warn.
   */
  error(...args: unknown[]) {
    if (enabled("error")) console.error(...scrubArgs(args));
    const errArg = args.find((a) => a instanceof Error);
    const msg = fmt(args);
    if (!sink) return;
    const { send, note } = admit(msg);
    if (!send) return;
    if (errArg) sink.captureError(errArg, msg + note);
    else sink.captureMessage(msg + note, "error");
  },
  /** Something a person must act on that is not a failure; always sent to Sentry, never throttled. */
  event(...args: unknown[]) {
    if (currentLevel !== "silent") console.warn(...scrubArgs(args));
    const msg = fmt(args);
    sink?.breadcrumb("warning", msg);
    sink?.captureMessage(msg, "warning");
  },
  /**
   * An event that can arrive in bursts, such as a filed report. The console
   * and breadcrumbs get every one; Sentry gets the first at once, then at most
   * one summary per SENTRY_BATCH_MS counting the rest, sent when the window
   * closes, so a flood cannot spend the quota and a quiet hour after it still
   * reports what arrived.
   */
  eventBatched(key: string, ...args: unknown[]) {
    if (currentLevel !== "silent") console.warn(...scrubArgs(args));
    const msg = fmt(args);
    sink?.breadcrumb("warning", msg);
    const now = clock();
    const b = batches.get(key);
    if (!b || (now >= b.until && b.held === 0)) {
      batches.set(key, { until: now + batchMs(), held: 0, timer: null });
      sink?.captureMessage(msg, "warning");
      return;
    }
    b.held++;
    if (!b.timer) {
      b.timer = setTimeout(() => flushBatch(key), Math.max(0, b.until - now));
      b.timer.unref();
    }
  },
  /** Operational lines printed at every level except silent. */
  startup(...args: unknown[]) {
    if (currentLevel !== "silent") console.log(...scrubArgs(args));
    sink?.breadcrumb("info", fmt(args));
  },
};

export type Logger = typeof logger;
