/**
 * The Postgres pool, query helpers and the sweeper for expiring rows. The
 * services connect through a transaction-mode PgBouncer pool, so session state
 * does not survive between statements (no SET, LISTEN/NOTIFY or session
 * advisory locks; multi-statement work goes through `tx`) and queries must not
 * use named prepared statements.
 */

import { logger } from "@hqchat/common/logger";
import { Pool, type PoolClient, type QueryResult, type QueryResultRow } from "pg";
import { tls, withoutSslMode } from "./ssl";

/** Client connections per process; keep within the pooler's `pool_size`. */
const POOL_MAX = Number(process.env.PG_POOL_MAX) || 3;

export const pool = new Pool({
  connectionString: withoutSslMode(process.env.DATABASE_URL),
  max: POOL_MAX,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  ssl: tls(process.env.DATABASE_URL),
});

// Without a listener, an idle client's error would crash the process.
pool.on("error", (err) => logger.error(`[pg] idle client: ${err.message}`));

/** Whether an error means the connection went away (restart, failover) rather than bad SQL. */
function isTransient(e: unknown): boolean {
  const err = e as { code?: string; message?: string };
  const code = err?.code || "";
  // admin/crash shutdown, cannot connect now, connection failures, too many connections.
  if (/^(57P0[123]|080(01|03|06)|53300)$/.test(code)) return true;
  return /ECONNRESET|ECONNREFUSED|ETIMEDOUT|EPIPE|Connection terminated/i.test(err?.message || "");
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * One query, retried once after a connection-level failure. Never more: a
 * repeated failure is an outage or a bug, and retrying a write of unknown
 * outcome is unsafe.
 */
export async function q<R extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = [],
): Promise<QueryResult<R>> {
  try {
    return await pool.query<R>(text, params);
  } catch (e) {
    if (!isTransient(e)) throw e;
    logger.warn(`[pg] transient: ${(e as Error).message} — retrying once`);
    await sleep(250);
    return await pool.query<R>(text, params);
  }
}

/** The first row, or null. */
export async function one<R extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = [],
): Promise<R | null> {
  const res = await q<R>(text, params);
  return res.rows[0] ?? null;
}

/** Runs `fn` in one transaction on one client. Not retried. */
export async function tx<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const out = await fn(client);
    await client.query("COMMIT");
    return out;
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // The connection is gone, and the transaction with it.
    }
    throw e;
  } finally {
    client.release();
  }
}

/** Tables whose rows carry their own expiry. */
const EXPIRING: Array<[table: string, column: string]> = [
  ["sessions", "expires_at"],
  ["auth_challenges", "expires_at"],
  ["mqtt_session_keys", "expires_at"],
  ["mqtt_nonces", "expires_at"],
  ["rate_counters", "window_ends_at"],
  ["reports", "expires_at"],
  ["ended_friendships", "expires_at"],
];

/**
 * Deletes lapsed rows and returns the count per table. Reads already filter on
 * expiry, so for most tables this only reclaims space; for `reports` it is the
 * published 90-day deletion, which `DB.listOpenReports` also enforces.
 */
export async function sweepExpired(): Promise<Record<string, number>> {
  const removed: Record<string, number> = {};
  for (const [table, column] of EXPIRING) {
    try {
      // Identifiers come from the literal list above.
      const res = await q(`DELETE FROM ${table} WHERE ${column} <= now()`);
      if (res.rowCount) removed[table] = res.rowCount;
    } catch (e) {
      logger.warn(`[pg] sweep ${table} failed: ${(e as Error).message}`);
    }
  }
  return removed;
}

/** Liveness probe. */
export async function ping(): Promise<boolean> {
  const res = await q<{ ok: number }>("SELECT 1 AS ok");
  return res.rows[0]?.ok === 1;
}

export async function disconnect(): Promise<void> {
  await pool.end();
}
