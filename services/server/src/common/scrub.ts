/**
 * Redaction of secrets and personal data from anything sent to Sentry or
 * printed. `redact` replaces sensitive shapes in text with typed placeholders;
 * `scrubDeep` also drops values under sensitive key names; `scrubEvent` and
 * `scrubBreadcrumb` apply both to Sentry payloads after dropping request,
 * host and user-network fields.
 *
 * `redact` and `isSensitiveKey` are mirrored by
 * apps/apple/HQChat/Helpers/Redaction.swift and kept identical by
 * test/fuzz/scrub-differential.ts. The patterns therefore use explicit ASCII
 * classes instead of \b and \s, whose meaning differs between V8 and ICU.
 */

const MAX_DEPTH = 6;
const MAX_STRING = 8192;

// Ordered from most to least specific, so broad hex/base64 rules run last.
const WB0 = "(?<![A-Za-z0-9_])";
const WB1 = "(?![A-Za-z0-9_])";
const WS = " \\t\\n\\r\\f\\x0B";

type Replacement = string | ((match: string, ...groups: string[]) => string);

const REDACTORS: Array<{ re: RegExp; to: Replacement }> = [
  { re: new RegExp(`${WB0}eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}${WB1}`, "g"), to: "[jwt]" },
  // URL userinfo credentials, e.g. postgresql://user:pw@host.
  {
    re: new RegExp(`${WB0}([a-z][a-z0-9+.-]*://)[^/${WS}:@]*:[^/${WS}@]+@`, "gi"),
    to: (_m: string, scheme: string) => `${scheme}[redacted]@`,
  },
  // key=value secrets in header, JSON, querystring or log form.
  {
    re: new RegExp(
      `${WB0}(authorization|auth|bearer|token|secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|dsn|cookie|session|stripe[_-]?signature|signature)${WB1}` +
        `([${WS}]*[:=][${WS}]*|[${WS}]+)("?)[^${WS},;"'}]+\\3`,
      "gi",
    ),
    to: (_m: string, k: string) => `${k}=[redacted]`,
  },
  { re: new RegExp(`${WB0}(?:sk|rk|whsec|pk)_[A-Za-z0-9_]{10,}${WB1}`, "g"), to: "[stripe-key]" },
  { re: new RegExp(`${WB0}t=\\d{10},v1=[a-f0-9]{16,}${WB1}`, "g"), to: "[stripe-sig]" },
  { re: new RegExp(`${WB0}[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}${WB1}`, "g"), to: "[email]" },
  // IPv6 (compressed, then full), then IPv4. One colon between groups keeps it linear.
  {
    re: new RegExp(
      `${WB0}(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*)?::(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*)?${WB1}`,
      "g",
    ),
    to: "[ip]",
  },
  { re: new RegExp(`${WB0}(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}${WB1}`, "g"), to: "[ip]" },
  {
    re: new RegExp(`${WB0}(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)${WB1}`, "g"),
    to: "[ip]",
  },
  // Keys and ciphertext: long hex or base64.
  { re: new RegExp(`${WB0}[A-Fa-f0-9]{32,}${WB1}`, "g"), to: "[key]" },
  { re: new RegExp(`${WB0}[A-Za-z0-9+/]{40,}={0,2}${WB1}`, "g"), to: "[blob]" },
  {
    re: new RegExp(`(^|[${WS}([{:,'"])@[A-Za-z0-9_]{2,32}${WB1}`, "g"),
    to: (_m: string, pre: string) => `${pre}@[user]`,
  },
];

/**
 * The string with sensitive shapes replaced, truncated to MAX_STRING Unicode
 * scalars (the unit Swift and JS can both count). Non-strings and "" pass through.
 */
export function redact(input: unknown): string {
  if (typeof input !== "string" || input.length === 0) return input as string;
  const scalars = Array.from(input);
  let s = scalars.length > MAX_STRING ? `${scalars.slice(0, MAX_STRING).join("")}…[truncated]` : input;
  for (const { re, to } of REDACTORS) {
    s = typeof to === "string" ? s.replace(re, to) : s.replace(re, to);
  }
  return s;
}

/** Key words (after camelCase/separator splitting) whose value is always redacted. */
const SENSITIVE_WORDS = new Set([
  "authorization",
  "auth",
  "bearer",
  "cookie",
  "token",
  "secret",
  "password",
  "passwd",
  "pwd",
  "apikey",
  "dsn",
  "session",
  "signature",
  "sig",
  "credential",
  "credentials",
  "pubkey",
  "payload",
  "ciphertext",
  "nonce",
  "ip",
]);
const SENSITIVE_PHRASES = [
  "publickey",
  "privatekey",
  "apikey",
  "accesskey",
  "secretkey",
  "ipaddress",
  "remoteaddress",
  "xforwardedfor",
];

function keyWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .map((w) => w.toLowerCase())
    .filter(Boolean);
}

/** Whether a key names a sensitive value: whole-word match, so "tripped" is not "ip". */
export function isSensitiveKey(key: string): boolean {
  const words = keyWords(key);
  if (words.some((w) => SENSITIVE_WORDS.has(w))) return true;
  const glued = words.join("");
  return SENSITIVE_PHRASES.some((p) => glued.includes(p));
}

/** A copy with strings redacted, sensitive keys' values replaced and depth bounded. */
export function scrubDeep<T>(value: T, depth = 0): T {
  if (depth > MAX_DEPTH) return "[max-depth]" as unknown as T;
  if (value == null) return value;
  if (typeof value === "string") return redact(value) as unknown as T;
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    return value.map((v) => scrubDeep(v, depth + 1)) as unknown as T;
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = isSensitiveKey(k) ? "[redacted]" : scrubDeep(v, depth + 1);
    }
    return out as unknown as T;
  }
  return value;
}

const record = (v: unknown): Record<string, unknown> | null =>
  typeof v === "object" && v !== null ? (v as Record<string, unknown>) : null;

/** Scrubs a Sentry breadcrumb in place and returns it. */
export function scrubBreadcrumb<T>(crumb: T): T {
  const c = record(crumb);
  if (!c) return crumb;
  if (typeof c.message === "string") c.message = redact(c.message);
  if (c.data) c.data = scrubDeep(c.data);
  return crumb;
}

/** Scrubs a Sentry event in place (drops request, host and user-network fields) and returns it. */
export function scrubEvent<T>(event: T): T {
  const e = record(event);
  if (!e) return event;

  delete e.request;
  delete e.server_name;
  const user = record(e.user);
  if (user) {
    delete user.ip_address;
    delete user.email;
    delete user.username;
  }

  if (typeof e.message === "string") e.message = redact(e.message);
  const logentry = record(e.logentry);
  if (logentry && typeof logentry.message === "string") logentry.message = redact(logentry.message);

  const values = record(e.exception)?.values;
  if (Array.isArray(values)) {
    for (const value of values) {
      const ex = record(value);
      if (!ex) continue;
      if (typeof ex.value === "string") ex.value = redact(ex.value);
      const frames = record(ex.stacktrace)?.frames;
      if (!Array.isArray(frames)) continue;
      for (const f of frames) {
        const frame = record(f);
        if (frame?.vars) frame.vars = scrubDeep(frame.vars);
      }
    }
  }

  const crumbs = record(e.breadcrumbs)?.values ?? e.breadcrumbs;
  if (Array.isArray(crumbs)) for (const c of crumbs) scrubBreadcrumb(c);

  for (const key of ["tags", "extra", "contexts"]) {
    if (e[key]) e[key] = scrubDeep(e[key]);
  }
  return event;
}
