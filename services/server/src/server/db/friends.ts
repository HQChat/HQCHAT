import { one, q, tx } from "./pg";

import { users } from "./users";

/** The random MQTT topic ids of one friendship. */
export interface FriendshipTopics {
  convoId: string;
  handshakeId: string;
}

function pair(a: string, b: string): [string, string] {
  return a < b ? [a, b] : [b, a];
}

/** The friend graph: invites, friendships with their topic ids, and blocks. */
export const friends = {
  /** Sends a friend invite. Throws `NOT_FOUND`, `SELF_INVITE` or `ALREADY_FRIENDS`. */
  async invite(fromId: string, toIdentifier: string): Promise<string> {
    const toId = await users.resolveToId(toIdentifier);
    if (toId === fromId) throw new Error("SELF_INVITE");
    if (!toId || !(await one(`SELECT 1 FROM users WHERE id = $1`, [toId]))) throw new Error("NOT_FOUND");
    if (await friends.areFriends(fromId, toId)) throw new Error("ALREADY_FRIENDS");
    await q(
      `INSERT INTO invites (to_id, from_id) VALUES ($1, $2)
       ON CONFLICT (to_id, from_id) DO UPDATE SET created_at = now()`,
      [toId, fromId],
    );
    return toId;
  },

  /** Withdraws an invite `fromId` sent. */
  async cancelInvite(fromId: string, toId: string): Promise<boolean> {
    const res = await q(`DELETE FROM invites WHERE to_id = $1 AND from_id = $2`, [toId, fromId]);
    return (res.rowCount ?? 0) > 0;
  },

  /** Declines an invite `myId` received. */
  async declineInvite(myId: string, fromId: string): Promise<boolean> {
    const res = await q(`DELETE FROM invites WHERE to_id = $1 AND from_id = $2`, [myId, fromId]);
    return (res.rowCount ?? 0) > 0;
  },

  /** Invites waiting for `myId`, oldest first. */
  async getMyInvites(myId: string): Promise<Array<{ id: string; username: string | null; sent_at: number }>> {
    const res = await q<{ id: string; username: string | null; sent_at: string }>(
      `SELECT i.from_id AS id, u.username::text AS username,
              (EXTRACT(epoch FROM i.created_at) * 1000)::bigint::text AS sent_at
         FROM invites i LEFT JOIN users u ON u.id = i.from_id
        WHERE i.to_id = $1
        ORDER BY i.created_at`,
      [myId],
    );
    return res.rows.map((r) => ({ id: r.id, username: r.username, sent_at: Number(r.sent_at) }));
  },

  /** Accepts a pending invite, creating the friendship. False when there was none. */
  async acceptInvite(fromId: string, myId: string): Promise<boolean> {
    return tx(async (c) => {
      const taken = await c.query(`DELETE FROM invites WHERE to_id = $1 AND from_id = $2`, [myId, fromId]);
      if (!taken.rowCount) return false;
      const [lo, hi] = pair(myId, fromId);
      await c.query(`INSERT INTO friendships (id_lo, id_hi) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [lo, hi]);
      return true;
    });
  },

  /** Creates a friendship directly (the onboarding bot). Idempotent. */
  async createFriendship(a: string, b: string): Promise<void> {
    const [lo, hi] = pair(a, b);
    await q(`INSERT INTO friendships (id_lo, id_hi) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [lo, hi]);
  },

  /** Every friend of `myId` with the friendship's topic ids. */
  async getFriendsList(
    myId: string,
  ): Promise<Array<{ id: string; username: string | null; convo_id: string; handshake_id: string }>> {
    const res = await q<{ id: string; username: string | null; convo_id: string; handshake_id: string }>(
      `SELECT peer.id, u.username::text AS username, f.convo_id, f.handshake_id
         FROM friendships f
         CROSS JOIN LATERAL (SELECT CASE WHEN f.id_lo = $1 THEN f.id_hi ELSE f.id_lo END AS id) peer
         LEFT JOIN users u ON u.id = peer.id
        WHERE f.id_lo = $1 OR f.id_hi = $1`,
      [myId],
    );
    return res.rows;
  },

  async getFriendshipTopics(a: string, b: string): Promise<FriendshipTopics | null> {
    const [lo, hi] = pair(a, b);
    const row = await one<{ convo_id: string; handshake_id: string }>(
      `SELECT convo_id, handshake_id FROM friendships WHERE id_lo = $1 AND id_hi = $2`,
      [lo, hi],
    );
    return row ? { convoId: row.convo_id, handshakeId: row.handshake_id } : null;
  },

  async countFriends(myId: string): Promise<number> {
    const row = await one<{ n: number }>(`SELECT count(*)::int AS n FROM friendships WHERE id_lo = $1 OR id_hi = $1`, [
      myId,
    ]);
    return row?.n ?? 0;
  },

  async areFriends(a: string, b: string): Promise<boolean> {
    const [lo, hi] = pair(a, b);
    return (await one(`SELECT 1 FROM friendships WHERE id_lo = $1 AND id_hi = $2`, [lo, hi])) !== null;
  },

  /** Ends a friendship and returns the topic ids it retired, or null when there was none. */
  async removeFriendship(a: string, b: string): Promise<FriendshipTopics | null> {
    const [lo, hi] = pair(a, b);
    const row = await one<{ convo_id: string; handshake_id: string }>(
      `DELETE FROM friendships WHERE id_lo = $1 AND id_hi = $2 RETURNING convo_id, handshake_id`,
      [lo, hi],
    );
    return row ? { convoId: row.convo_id, handshakeId: row.handshake_id } : null;
  },

  /** The two members of the friendship whose conversation topic is `cv/{convoId}`. */
  async getTopicMembers(convoId: string): Promise<string[]> {
    const row = await one<{ id_lo: string; id_hi: string }>(
      `SELECT id_lo, id_hi FROM friendships WHERE convo_id = $1`,
      [convoId],
    );
    return row ? [row.id_lo, row.id_hi] : [];
  },

  async block(blockerId: string, blockedId: string): Promise<void> {
    await q(`INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [
      blockerId,
      blockedId,
    ]);
  },

  async unblock(blockerId: string, blockedId: string): Promise<boolean> {
    const res = await q(`DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2`, [blockerId, blockedId]);
    return (res.rowCount ?? 0) > 0;
  },

  /** Whether either party blocked the other. */
  async isBlocked(a: string, b: string): Promise<boolean> {
    const row = await one(
      `SELECT 1 FROM blocks
        WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $2 AND blocked_id = $1)`,
      [a, b],
    );
    return row !== null;
  },

  async blockedIds(myId: string): Promise<string[]> {
    const res = await q<{ blocked_id: string }>(
      `SELECT blocked_id FROM blocks WHERE blocker_id = $1 ORDER BY created_at`,
      [myId],
    );
    return res.rows.map((r) => r.blocked_id);
  },
};
