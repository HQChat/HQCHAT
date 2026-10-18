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

/** Accounts: identities, usernames and account deletion. */
export const users = {
  /** Records an identity: its id and the public key it names. Idempotent. */
  async ensureUser(id: string, identityPk: string): Promise<void> {
    await q(`INSERT INTO users (id, identity_pk) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, [
      id,
      identityPk.toLowerCase(),
    ]);
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

  /** Deletes an account and everything stored about it, except reports filed against it. */
  async deleteUser(id: string): Promise<void> {
    await tx(async (c) => {
      await c.query(`DELETE FROM friendships WHERE id_lo = $1 OR id_hi = $1`, [id]);
      await c.query(`DELETE FROM invites WHERE to_id = $1 OR from_id = $1`, [id]);
      await c.query(`DELETE FROM mqtt_session_keys WHERE id = $1`, [id]);
      await c.query(`DELETE FROM sessions WHERE id = $1`, [id]);
      await c.query(`DELETE FROM push_tokens WHERE id = $1`, [id]);
      await c.query(`DELETE FROM prekeys_medium WHERE id = $1`, [id]);
      await c.query(`DELETE FROM prekeys_onetime WHERE id = $1`, [id]);
      await c.query(`DELETE FROM blocks WHERE blocker_id = $1 OR blocked_id = $1`, [id]);
      await c.query(`UPDATE reports SET reporter_id = NULL WHERE reporter_id = $1`, [id]);
      await c.query(`DELETE FROM users WHERE id = $1`, [id]);
    });
  },
};
