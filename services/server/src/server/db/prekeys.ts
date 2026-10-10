import { one, tx } from "./pg";

/** Prekey bundles: one medium-term prekey and a pool of one-time prekeys per account. */
export const prekeys = {
  /** Replaces the medium-term prekey and adds one-time prekeys (existing ids are kept). */
  async putPrekeyBundle(ownerId: string, mediumPrekey: string, oneTime: Array<{ id: number; prekey: string }>) {
    await tx(async (c) => {
      await c.query(
        `INSERT INTO prekeys_medium (id, prekey, updated_at) VALUES ($1, $2, now())
         ON CONFLICT (id) DO UPDATE SET prekey = EXCLUDED.prekey, updated_at = now()`,
        [ownerId, mediumPrekey],
      );
      if (oneTime.length === 0) return;
      await c.query(
        `INSERT INTO prekeys_onetime (id, key_id, prekey)
         SELECT $1, * FROM unnest($2::int[], $3::text[])
         ON CONFLICT (id, key_id) DO NOTHING`,
        [ownerId, oneTime.map((k) => k.id), oneTime.map((k) => k.prekey)],
      );
    });
  },

  /**
   * The bundle an initiator needs: the medium-term prekey, plus one one-time
   * prekey (consumed exactly once) while any remain. Null when nothing is published.
   */
  async claimPrekey(
    ownerId: string,
  ): Promise<{ medium: string; oneTime: { id: number; prekey: string } | null } | null> {
    const medium = await one<{ prekey: string }>(`SELECT prekey FROM prekeys_medium WHERE id = $1`, [ownerId]);
    if (!medium) return null;
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
