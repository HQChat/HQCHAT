import { logger } from "../../common/logger";
import { one, tx } from "./pg";

/** One-time prekeys kept per account; an upload past it drops the oldest. */
const ONETIME_POOL_MAX = 32;
/**
 * One-time prekeys kept across every account (each is about 14.5 kB). Past
 * it, uploads still rotate the medium-term key but store no one-time keys.
 */
const ONETIME_TOTAL_MAX = Number(process.env.PREKEY_ONETIME_TOTAL_MAX) || 250_000;

let storageCheck = { at: 0, full: false };

/**
 * Whether the one-time table is past ONETIME_TOTAL_MAX, from the planner's
 * row estimate (no table scan), re-read at most once a minute.
 */
async function oneTimeStorageFull(): Promise<boolean> {
  if (Date.now() - storageCheck.at < 60_000) return storageCheck.full;
  const row = await one<{ n: string }>(
    `SELECT greatest(reltuples, 0)::bigint::text AS n FROM pg_class WHERE oid = 'prekeys_onetime'::regclass`,
  );
  const full = Number(row?.n ?? 0) >= ONETIME_TOTAL_MAX;
  if (full) logger.error(`[prekeys] one-time prekey storage is past ${ONETIME_TOTAL_MAX} rows; storing none`);
  storageCheck = { at: Date.now(), full };
  return full;
}

/** Prekey bundles: one medium-term prekey and a pool of one-time prekeys per account. */
export const prekeys = {
  ONETIME_POOL_MAX,

  /**
   * Replaces the medium-term prekey and adds one-time prekeys (existing ids
   * are kept), keeping the newest ONETIME_POOL_MAX. Returns how many one-time
   * keys were offered for storage: none while total storage is full.
   */
  async putPrekeyBundle(
    ownerId: string,
    mediumPrekey: string,
    oneTime: Array<{ id: number; prekey: string }>,
  ): Promise<number> {
    const store = oneTime.length > 0 && !(await oneTimeStorageFull());
    await tx(async (c) => {
      await c.query(
        `INSERT INTO prekeys_medium (id, prekey, updated_at) VALUES ($1, $2, now())
         ON CONFLICT (id) DO UPDATE SET prekey = EXCLUDED.prekey, updated_at = now()`,
        [ownerId, mediumPrekey],
      );
      if (!store) return;
      await c.query(
        `INSERT INTO prekeys_onetime (id, key_id, prekey)
         SELECT $1, * FROM unnest($2::int[], $3::text[])
         ON CONFLICT (id, key_id) DO NOTHING`,
        [ownerId, oneTime.map((k) => k.id), oneTime.map((k) => k.prekey)],
      );
      await c.query(
        `DELETE FROM prekeys_onetime
          WHERE id = $1
            AND key_id NOT IN (SELECT key_id FROM prekeys_onetime WHERE id = $1
                                ORDER BY created_at DESC, key_id DESC LIMIT $2)`,
        [ownerId, ONETIME_POOL_MAX],
      );
    });
    return store ? oneTime.length : 0;
  },

  /**
   * The bundle an initiator needs: the medium-term prekey, plus one one-time
   * prekey (consumed exactly once) while any remain and `takeOneTime` allows.
   * Null when nothing is published.
   */
  async claimPrekey(
    ownerId: string,
    takeOneTime = true,
  ): Promise<{ medium: string; oneTime: { id: number; prekey: string } | null } | null> {
    const medium = await one<{ prekey: string }>(`SELECT prekey FROM prekeys_medium WHERE id = $1`, [ownerId]);
    if (!medium) return null;
    if (!takeOneTime) return { medium: medium.prekey, oneTime: null };
    const oneTime = await one<{ key_id: number; prekey: string }>(
      `DELETE FROM prekeys_onetime
        WHERE ctid = (SELECT ctid FROM prekeys_onetime WHERE id = $1 ORDER BY key_id LIMIT 1 FOR UPDATE SKIP LOCKED)
        RETURNING key_id, prekey`,
      [ownerId],
    );
    return { medium: medium.prekey, oneTime: oneTime ? { id: oneTime.key_id, prekey: oneTime.prekey } : null };
  },

  async countOneTimePrekeys(ownerId: string): Promise<number> {
    const row = await one<{ n: number }>(`SELECT count(*)::int AS n FROM prekeys_onetime WHERE id = $1`, [ownerId]);
    return row?.n ?? 0;
  },

  /** Highest one-time prekey id on file, or null when the pool is empty. */
  async maxOneTimePrekeyId(ownerId: string): Promise<number | null> {
    const row = await one<{ key_id: number | null }>(
      `SELECT max(key_id) AS key_id FROM prekeys_onetime WHERE id = $1`,
      [ownerId],
    );
    return row?.key_id ?? null;
  },
};
