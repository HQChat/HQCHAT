/**
 * First-time App Store downloads, from App Store Connect's Sales and Trends
 * reports: the one count of installs the server cannot see for itself.
 *
 *   ASC_SALES_KEY_ID      an App Store Connect API key with the Sales role only
 *   ASC_SALES_ISSUER_ID   its issuer id
 *   ASC_SALES_KEY_P8      its private key, PEM (ASC_SALES_KEY_P8_FILE)
 *   ASC_VENDOR_NUMBER     Payments and Financial Reports → vendor number
 *   ASC_SALES_START       first day to count, YYYY-MM-DD (the launch)
 *
 * Deliberately not the CI key (ASC_KEY_*): that one can upload builds.
 *
 * Apple publishes a day's report the next day, so the latest figure is for
 * yesterday at best. Each fetched day is cached in `app_downloads`, so the
 * all-time figure is a sum and a day is fetched once.
 */

import * as crypto from "node:crypto";
import * as zlib from "node:zlib";

const API = "https://api.appstoreconnect.apple.com/v1/salesReports";
/** Apple refuses tokens that live longer than 20 minutes. */
const TOKEN_TTL_SECONDS = 15 * 60;
/** Days fetched per run, so a first run cannot hammer the API. */
export const MAX_DAYS_PER_RUN = 365;
/**
 * Product types that are a first-time download: iPhone/iPod, universal, iPad
 * and Mac apps. Redownloads (3*) and updates (7*) are left out.
 */
const FIRST_TIME = new Set(["1", "1F", "1T", "F1"]);
const DAY = /^\d{4}-\d{2}-\d{2}$/;

export interface SalesConfig {
  keyId: string;
  issuerId: string;
  privateKey: string;
  vendorNumber: string;
  start: string;
}

/** The configuration from the environment, null when any part is missing, or an error naming the bad part. */
export function salesConfig(env: NodeJS.ProcessEnv = process.env): SalesConfig | null {
  const keyId = env.ASC_SALES_KEY_ID?.trim() || "";
  const issuerId = env.ASC_SALES_ISSUER_ID?.trim() || "";
  const privateKey = env.ASC_SALES_KEY_P8?.trim() || "";
  const vendorNumber = env.ASC_VENDOR_NUMBER?.trim() || "";
  const start = env.ASC_SALES_START?.trim() || "";
  if (!keyId || !issuerId || !privateKey || !vendorNumber || !start) return null;
  if (!DAY.test(start) || addDays(start, 0) !== start) throw new Error(`ASC_SALES_START=${start} is not YYYY-MM-DD`);
  if (!/^\d+$/.test(vendorNumber)) throw new Error("ASC_VENDOR_NUMBER is not a number");
  return { keyId, issuerId, privateKey, vendorNumber, start };
}

const b64url = (b: Buffer) => b.toString("base64url");

/** A signed ES256 token for the App Store Connect API, valid for 15 minutes from `nowSeconds`. */
export function salesToken(cfg: SalesConfig, nowSeconds: number): string {
  const header = b64url(Buffer.from(JSON.stringify({ alg: "ES256", kid: cfg.keyId, typ: "JWT" })));
  const payload = b64url(
    Buffer.from(
      JSON.stringify({
        iss: cfg.issuerId,
        iat: nowSeconds,
        exp: nowSeconds + TOKEN_TTL_SECONDS,
        aud: "appstoreconnect-v1",
      }),
    ),
  );
  const signature = crypto.sign("sha256", Buffer.from(`${header}.${payload}`), {
    key: cfg.privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${header}.${payload}.${b64url(signature)}`;
}

/** First-time units in one daily summary report, and the rows that could not be read. */
export function parseSummary(tsv: string): { units: number; malformed: number } {
  const lines = tsv.split(/\r?\n/).filter((l) => l.trim() !== "");
  const header = lines.shift()?.split("\t") ?? [];
  const typeAt = header.indexOf("Product Type Identifier");
  const unitsAt = header.indexOf("Units");
  if (typeAt < 0 || unitsAt < 0) throw new Error("the sales report has no Product Type Identifier or Units column");
  let units = 0;
  let malformed = 0;
  for (const line of lines) {
    const cols = line.split("\t");
    const type = cols[typeAt]?.trim();
    const raw = cols[unitsAt]?.trim() ?? "";
    if (cols.length !== header.length || !type || !/^-?\d+$/.test(raw)) {
      malformed++;
      continue;
    }
    if (FIRST_TIME.has(type)) units += Number(raw);
  }
  if (!Number.isSafeInteger(units) || units < 0) throw new Error(`the sales report sums to ${units} first-time units`);
  return { units, malformed };
}

/** `day` moved by `n` days, YYYY-MM-DD in UTC. */
export function addDays(day: string, n: number): string {
  const [y, m, d] = day.split("-").map(Number);
  return new Date(Date.UTC(y ?? 0, (m ?? 1) - 1, (d ?? 1) + n)).toISOString().slice(0, 10);
}

/** One day's report: its units, `none` (no sales that day) or `pending` (not published yet). */
export type DayReport = { units: number; malformed: number } | "none" | "pending";

/**
 * Fetches one day's summary. A 404 is Apple's answer both for a day without
 * sales and for a report not out yet; it is read as `none` only once the day
 * is two days old, and as `pending` before that.
 */
export async function fetchDay(cfg: SalesConfig, day: string, today: string, nowSeconds: number): Promise<DayReport> {
  const params = new URLSearchParams({
    "filter[frequency]": "DAILY",
    "filter[reportType]": "SALES",
    "filter[reportSubType]": "SUMMARY",
    "filter[version]": "1_1",
    "filter[vendorNumber]": cfg.vendorNumber,
    "filter[reportDate]": day,
  });
  const res = await fetch(`${API}?${params}`, {
    headers: { authorization: `Bearer ${salesToken(cfg, nowSeconds)}`, accept: "application/a-gzip" },
    signal: AbortSignal.timeout(30_000),
  });
  if (res.status === 404) return day <= addDays(today, -2) ? "none" : "pending";
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as { errors?: Array<{ code?: unknown }> } | null;
    const code = typeof body?.errors?.[0]?.code === "string" ? ` ${body.errors[0].code}` : "";
    throw new Error(`sales report ${day} → ${res.status}${code}`);
  }
  const bytes = Buffer.from(await res.arrayBuffer());
  // Gzip unless the transport already undid it.
  const gz = bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
  return parseSummary((gz ? zlib.gunzipSync(bytes) : bytes).toString("utf8"));
}

/** Where fetched days are kept (db/usage.ts). */
export interface DownloadStore {
  downloadDaysSince(since: string): Promise<Set<string>>;
  recordDownloads(day: string, units: number): Promise<void>;
}

/** What one refresh did. */
export interface RefreshResult {
  fetched: number;
  pending: string[];
  malformed: number;
  /** Days still missing because of the per-run cap. */
  remaining: number;
}

/**
 * Fetches and caches every day from `cfg.start` to yesterday that is not
 * cached yet, oldest first, at most MAX_DAYS_PER_RUN of them. Stops at the
 * first error, keeping what was cached before it.
 */
export async function refreshDownloads(
  cfg: SalesConfig,
  store: DownloadStore,
  today: string,
  clock: () => number = () => Math.floor(Date.now() / 1000),
): Promise<RefreshResult> {
  const cached = await store.downloadDaysSince(cfg.start);
  const missing: string[] = [];
  for (let day = cfg.start; day < today; day = addDays(day, 1)) if (!cached.has(day)) missing.push(day);
  const result: RefreshResult = { fetched: 0, pending: [], malformed: 0, remaining: 0 };
  const batch = missing.slice(0, MAX_DAYS_PER_RUN);
  result.remaining = missing.length - batch.length;
  for (const day of batch) {
    // A fresh token per request: a long backfill outlives any one token.
    const report = await fetchDay(cfg, day, today, clock());
    if (report === "pending") {
      result.pending.push(day);
      continue;
    }
    const units = report === "none" ? 0 : report.units;
    if (report !== "none") result.malformed += report.malformed;
    await store.recordDownloads(day, units);
    result.fetched++;
  }
  return result;
}
