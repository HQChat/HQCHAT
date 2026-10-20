import type { PoolClient } from "pg";
import { isPeerId } from "../../common/core";
import { one, q, tx } from "./pg";

const RESERVED_USERNAMES = new Set([
  "admin",
  "administrator",
  "root",
  "system",
  "support",
  "help",
  "contact",
  "info",
  "security",
  "test",
  "tester",
  "bot",
  "moderator",
  "mod",
  "staff",
  "team",
  "owner",
  "founder",
  "helper",
  "hqchat",
]);

/**
 * Deletes everything stored about an account, except reports filed against it
 * and blocks other users placed on it: those are the other users' data, and
 * dropping them would let a blocked account lift every block on it by
 * deleting itself and signing back in with the same key.
 */
async function deleteAccountRows(c: PoolClient, id: string): Promise<void> {
  await c.query(`DELETE FROM friendships WHERE id_lo = $1 OR id_hi = $1`, [id]);
  await c.query(`DELETE FROM invites WHERE to_id = $1 OR from_id = $1`, [id]);
  await c.query(`DELETE FROM mqtt_session_keys WHERE id = $1`, [id]);
  await c.query(`DELETE FROM sessions WHERE id = $1`, [id]);
  await c.query(`DELETE FROM push_tokens WHERE id = $1`, [id]);
  await c.query(`DELETE FROM prekeys_medium WHERE id = $1`, [id]);
  await c.query(`DELETE FROM prekeys_onetime WHERE id = $1`, [id]);
  await c.query(`DELETE FROM blocks WHERE blocker_id = $1`, [id]);
  await c.query(`UPDATE reports SET reporter_id = NULL WHERE reporter_id = $1`, [id]);
  await c.query(`DELETE FROM users WHERE id = $1`, [id]);
}

/** Accounts: identities, usernames, account deletion and bans. */
export const users = {
  /**
   * Records an identity: its id and the public key it names. Idempotent.
   * Throws `BANNED` for an id an operator banned, and records nothing.
   */
  async ensureUser(id: string, identityPk: string): Promise<void> {
    const res = await q(
      `INSERT INTO users (id, identity_pk)
       SELECT $1, $2 WHERE NOT EXISTS (SELECT 1 FROM banned_ids WHERE id = $1)
       ON CONFLICT (id) DO NOTHING`,
      [id, identityPk.toLowerCase()],
    );
    if (!res.rowCount && (await users.isBanned(id))) throw new Error("BANNED");
  },

  /** Whether an operator banned this id. */
  async isBanned(id: string): Promise<boolean> {
    return (await one(`SELECT 1 FROM banned_ids WHERE id = $1`, [id])) !== null;
  },

  /**
   * Bans an id: records it, so its key cannot sign in again, and deletes the
   * account as `deleteUser` does, in one transaction.
   */
  async banUser(id: string): Promise<void> {
    await tx(async (c) => {
      await c.query(`INSERT INTO banned_ids (id) VALUES ($1) ON CONFLICT DO NOTHING`, [id]);
      await deleteAccountRows(c, id);
    });
  },

  async getUsername(id: string): Promise<string | null> {
    const row = await one<{ username: string | null }>(`SELECT username FROM users WHERE id = $1`, [id]);
    return row?.username ?? null;
  },

  /** The public key an id names. Callers must verify it with `keyMatchesId`. */
  async identityKey(id: string): Promise<string | null> {
    const row = await one<{ identity_pk: string }>(`SELECT identity_pk FROM users WHERE id = $1`, [id]);
    return row?.identity_pk ?? null;
  },

  /** Case-insensitive username lookup. */
  async getIdByUsername(username: string): Promise<string | null> {
    const row = await one<{ id: string }>(`SELECT id FROM users WHERE username = $1`, [username]);
    return row?.id ?? null;
  },

  /** Resolves an identifier that is either a client id or a username. */
  async resolveToId(identifier: string): Promise<string | null> {
    if (!identifier) return null;
    const lowered = identifier.toLowerCase();
    if (isPeerId(lowered)) return lowered;
    return users.getIdByUsername(identifier);
  },

  /**
   * Claims a username for `id`. Reserved names are claimable only by
   * `reservedOwner` (the deployment's bot). Throws `USERNAME_TAKEN`,
   * `USERNAME_RESERVED`, `INVALID_USERNAME` or `UNKNOWN_IDENTITY`.
   */
  async setUsername(id: string, username: string, reservedOwner: string | null = null): Promise<void> {
    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) throw new Error("INVALID_USERNAME");
    if (RESERVED_USERNAMES.has(username.toLowerCase()) && id !== reservedOwner) throw new Error("USERNAME_RESERVED");
    const owner = await users.getIdByUsername(username);
    if (owner === id) return;
    if (owner) throw new Error("USERNAME_TAKEN");
    const res = await q(`UPDATE users SET username = $2 WHERE id = $1`, [id, username]);
    if (!res.rowCount) throw new Error("UNKNOWN_IDENTITY");
  },

  /**
   * Deletes an account and everything stored about it, except reports filed
   * against it and blocks other users placed on it.
   */
  async deleteUser(id: string): Promise<void> {
    await tx((c) => deleteAccountRows(c, id));
  },
};
