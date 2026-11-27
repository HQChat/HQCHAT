import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { test } from "node:test";
import * as zlib from "node:zlib";
import {
  addDays,
  type DownloadStore,
  fetchDay,
  MAX_DAYS_PER_RUN,
  parseSummary,
  refreshDownloads,
  type SalesConfig,
  salesConfig,
  salesToken,
} from "../../src/server/appstore-sales";

const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });

const CFG: SalesConfig = {
  keyId: "KEY123",
  issuerId: "issuer-uuid",
  privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  vendorNumber: "8765432",
  start: "2026-10-20",
};

const savedFetch = globalThis.fetch;
test.after(() => {
  globalThis.fetch = savedFetch;
});

const HEADER = ["Provider", "SKU", "Units", "Product Type Identifier", "Country Code"].join("\t");
const tsv = (...rows: string[][]) => [HEADER, ...rows.map((r) => r.join("\t"))].join("\n");

test("the token is ES256 for App Store Connect and verifies with the key", () => {
  const token = salesToken(CFG, 1_000_000);
  const [h, p, s] = token.split(".");
  const header = JSON.parse(Buffer.from(h!, "base64url").toString());
  const payload = JSON.parse(Buffer.from(p!, "base64url").toString());
  assert.deepEqual(header, { alg: "ES256", kid: "KEY123", typ: "JWT" });
  assert.equal(payload.iss, "issuer-uuid");
  assert.equal(payload.aud, "appstoreconnect-v1");
  assert.equal(payload.iat, 1_000_000);
  assert.ok(payload.exp - payload.iat <= 20 * 60, "Apple refuses tokens over 20 minutes");
  const ok = crypto.verify(
    "sha256",
    Buffer.from(`${h}.${p}`),
    { key: publicKey, dsaEncoding: "ieee-p1363" },
    Buffer.from(s!, "base64url"),
  );
  assert.equal(ok, true);
});

test("only first-time downloads are summed", () => {
  const r = parseSummary(
    tsv(
      ["APPLE", "hqchat", "5", "1", "FR"],
      ["APPLE", "hqchat", "2", "1F", "US"],
      ["APPLE", "hqchat", "1", "F1", "DE"],
      ["APPLE", "hqchat", "9", "3F", "FR"], // redownload
      ["APPLE", "hqchat", "40", "7F", "FR"], // update
    ),
  );
  assert.deepEqual(r, { units: 8, malformed: 0 });
});

test("a row that cannot be read is counted as malformed, not skipped silently", () => {
  const r = parseSummary(
    tsv(["APPLE", "hqchat", "x", "1", "FR"], ["APPLE", "hqchat", "3", "1"], ["APPLE", "hqchat", "4", "1", "FR"]),
  );
  assert.deepEqual(r, { units: 4, malformed: 2 });
});

test("a report without the columns is an error", () => {
  assert.throws(() => parseSummary("Provider\tSKU\nAPPLE\thqchat"), /no Product Type Identifier or Units/);
});

test("the configuration is all or nothing, and a bad start date is named", () => {
  assert.equal(salesConfig({ ASC_SALES_KEY_ID: "K" }), null);
  const full = {
    ASC_SALES_KEY_ID: "K",
    ASC_SALES_ISSUER_ID: "I",
    ASC_SALES_KEY_P8: "PEM",
    ASC_VENDOR_NUMBER: "123",
    ASC_SALES_START: "2026-10-01",
  };
  assert.equal(salesConfig(full)?.start, "2026-10-01");
  assert.throws(() => salesConfig({ ...full, ASC_SALES_START: "2026-02-30" }), /ASC_SALES_START/);
  assert.throws(() => salesConfig({ ...full, ASC_VENDOR_NUMBER: "abc" }), /ASC_VENDOR_NUMBER/);
});

test("days step across months and years in UTC", () => {
  assert.equal(addDays("2026-12-31", 1), "2027-01-01");
  assert.equal(addDays("2026-03-01", -1), "2026-02-28");
});

/** Answers each reportDate from `byDay`: a TSV (gzipped), or a status. */
function apple(byDay: Record<string, string | number>) {
  const asked: string[] = [];
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    const u = new URL(url);
    assert.equal(u.origin + u.pathname, "https://api.appstoreconnect.apple.com/v1/salesReports");
    assert.match((init.headers as Record<string, string>).authorization ?? "", /^Bearer [\w-]+\.[\w-]+\.[\w-]+$/);
    const day = u.searchParams.get("filter[reportDate]") ?? "";
    asked.push(day);
    const answer = byDay[day] ?? 404;
    if (typeof answer === "number") {
      return new Response(JSON.stringify({ errors: [{ code: answer === 404 ? "NOT_FOUND" : "FORBIDDEN" }] }), {
        status: answer,
      });
    }
    return new Response(zlib.gzipSync(answer), { status: 200 });
  }) as typeof fetch;
  return asked;
}

test("a 404 is no sales once the day is two days old, and not yet published before", async () => {
  apple({});
  assert.equal(await fetchDay(CFG, "2026-10-23", "2026-10-25", 0), "none");
  assert.equal(await fetchDay(CFG, "2026-10-24", "2026-10-25", 0), "pending");
});

test("any other refusal is an error that names the status and Apple's code", async () => {
  apple({ "2026-10-20": 403 });
  await assert.rejects(() => fetchDay(CFG, "2026-10-20", "2026-10-25", 0), /2026-10-20 → 403 FORBIDDEN/);
});

function memoryStore(cached: Record<string, number> = {}): DownloadStore & { days: Record<string, number> } {
  const days = { ...cached };
  return {
    days,
    async downloadDaysSince(since) {
      return new Set(Object.keys(days).filter((d) => d >= since));
    },
    async recordDownloads(day, units) {
      days[day] = units;
    },
  };
}

test("a refresh fetches only the missing days up to yesterday and keeps yesterday open", async () => {
  const asked = apple({ "2026-10-22": tsv(["APPLE", "hqchat", "6", "1F", "FR"]) });
  const store = memoryStore({ "2026-10-20": 3 });
  const r = await refreshDownloads(CFG, store, "2026-10-25");
  assert.deepEqual(asked, ["2026-10-21", "2026-10-22", "2026-10-23", "2026-10-24"]);
  assert.deepEqual(store.days, { "2026-10-20": 3, "2026-10-21": 0, "2026-10-22": 6, "2026-10-23": 0 });
  assert.deepEqual(r, { fetched: 3, pending: ["2026-10-24"], malformed: 0, remaining: 0 });
});

test("a first run is capped and says how many days are left", async () => {
  apple({});
  const cfg = { ...CFG, start: addDays("2026-10-25", -(MAX_DAYS_PER_RUN + 10)) };
  const r = await refreshDownloads(cfg, memoryStore(), "2026-10-25");
  assert.equal(r.fetched, MAX_DAYS_PER_RUN);
  assert.equal(r.remaining, 10);
});
