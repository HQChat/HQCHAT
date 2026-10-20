import * as crypto from "node:crypto";
import { one, q } from "./pg";

/** Lifetime of a registered MQTT signing key (the key a CONNECT proof is signed with). */
const MQTT_KEY_TTL_SECONDS = 12 * 60 * 60;
/** Idle timeout of a REST session; every use slides it. */
const REST_SESSION_TTL_SECONDS = 60 * 60;
/** Absolute cap on a REST session, however active. */
const REST_SESSION_MAX_AGE_SECONDS = 30 * 24 * 60 * 60;
/** A session is only re-written once it is within this window of lapsing. */
const SESSION_SLIDE_AFTER_SECONDS = 5 * 60;
const AUTH_CHALLENGE_TTL_SECONDS = 60;
/** Open challenges one source address keeps per identity; its older ones are dropped. */
const AUTH_CHALLENGES_PER_SOURCE = 4;
/**
 * Open challenges a verify without a challenge id is compared against, newest
 * first. Bounds the work strangers can add to the owner's verify; the owner's
 * own challenge is seconds old, so it is among the newest.
 */
const AUTH_CHALLENGES_COMPARED = 256;

/** The authenticated caller of a REST request. */
export interface SessionInfo {
  /** The caller's client id. */
  id: string;
}

function tokenHash(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

const secs = (n: number) => `${Math.max(0, Math.floor(n))} seconds`;

/**
 * Short-lived authentication state: MQTT signing keys, CONNECT nonces, sign-in
 * challenges, REST sessions and rate counters.
 */
export const sessions = {
  MQTT_KEY_TTL_SECONDS,

  /**
   * Registers the public half of a client's per-session Ed25519 signing key and
   * returns its id and expiry. Keeps the two newest keys per client.
   */
  async registerMqttKey(id: string, publicKey: Buffer): Promise<{ keyId: string; expiresAt: number }> {
    if (publicKey.length !== 32) throw new Error("an Ed25519 public key is 32 bytes");
    const keyId = crypto.randomBytes(16).toString("hex");
    const row = await one<{ expire_at: string }>(
      `INSERT INTO mqtt_session_keys (id, key_id, pubkey, expires_at)
       VALUES ($1, $2, $3, now() + $4::interval)
       RETURNING EXTRACT(epoch FROM expires_at)::bigint::text AS expire_at`,
      [id, keyId, publicKey, secs(MQTT_KEY_TTL_SECONDS)],
    );
    await q(
      `DELETE FROM mqtt_session_keys
        WHERE id = $1
          AND (expires_at <= now()
               OR key_id NOT IN (SELECT key_id FROM mqtt_session_keys WHERE id = $1
                                  ORDER BY created_at DESC, key_id LIMIT 2))`,
      [id],
    );
    return { keyId, expiresAt: Number(row?.expire_at) };
  },

  /** The live signing key a CONNECT proof names, or null. */
  async getMqttSessionKey(id: string, keyId: string): Promise<{ publicKey: Buffer; expireAt: number } | null> {
    const row = await one<{ pubkey: Buffer; expire_at: string }>(
      `SELECT pubkey, EXTRACT(epoch FROM expires_at)::bigint::text AS expire_at
         FROM mqtt_session_keys WHERE id = $1 AND key_id = $2 AND expires_at > now()`,
      [id, keyId],
    );
    return row ? { publicKey: row.pubkey, expireAt: Number(row.expire_at) } : null;
  },

  /** Drops every signing key of a client, so no new CONNECT verifies. */
  async revokeMqttKeys(id: string): Promise<void> {
    await q(`DELETE FROM mqtt_session_keys WHERE id = $1`, [id]);
  },

  /** True the first time a nonce is seen within `ttlSeconds`; false on replay. */
  async useNonce(nonce: string, ttlSeconds: number): Promise<boolean> {
    const res = await q(
      `INSERT INTO mqtt_nonces (nonce, expires_at) VALUES ($1, now() + $2::interval)
       ON CONFLICT (nonce) DO UPDATE SET expires_at = EXCLUDED.expires_at
       WHERE mqtt_nonces.expires_at <= now()
       RETURNING nonce`,
      [nonce, secs(ttlSeconds)],
    );
    return (res.rowCount ?? 0) === 1;
  },

  /**
   * Opens a sign-in challenge for `id` with its expected KEM proof and returns
   * the challenge id. Other open challenges stay open: `source` (a hash of the
   * caller's address) keeps only its newest AUTH_CHALLENGES_PER_SOURCE, so one
   * caller's inits never displace another's.
   */
  async startAuthChallenge(id: string, source: string, proofHex: string): Promise<string> {
    const challengeId = crypto.randomBytes(16).toString("hex");
    await q(
      `INSERT INTO auth_challenges (id, challenge_id, source, proof, expires_at)
       VALUES ($1, $2, $3, $4, now() + $5::interval)`,
      [id, challengeId, source, proofHex, secs(AUTH_CHALLENGE_TTL_SECONDS)],
    );
    await q(
      `DELETE FROM auth_challenges
        WHERE id = $1
          AND (expires_at <= now()
               OR (source = $2
                   AND challenge_id NOT IN (SELECT challenge_id FROM auth_challenges
                                             WHERE id = $1 AND source = $2
                                             ORDER BY created_at DESC, challenge_id LIMIT $3)))`,
      [id, source, AUTH_CHALLENGES_PER_SOURCE],
    );
    return challengeId;
  },

  /** The open challenges for `id`, newest first and at most AUTH_CHALLENGES_COMPARED. */
  async openAuthChallenges(id: string): Promise<Array<{ challengeId: string; proof: string }>> {
    const res = await q<{ challenge_id: string; proof: string }>(
      `SELECT challenge_id, proof FROM auth_challenges
        WHERE id = $1 AND expires_at > now()
        ORDER BY created_at DESC, challenge_id LIMIT $2`,
      [id, AUTH_CHALLENGES_COMPARED],
    );
    return res.rows.map((r) => ({ challengeId: r.challenge_id, proof: r.proof }));
  },

  /** Spends one open challenge; false when it was already spent or has lapsed. */
  async spendAuthChallenge(id: string, challengeId: string): Promise<boolean> {
    const res = await q(`DELETE FROM auth_challenges WHERE id = $1 AND challenge_id = $2 AND expires_at > now()`, [
      id,
      challengeId,
    ]);
    return (res.rowCount ?? 0) === 1;
  },

  /** Mints a REST session bearer; returns the raw token (stored only hashed). */
  async mintSessionToken(id: string): Promise<string> {
    const token = crypto.randomBytes(32).toString("hex");
    await q(`INSERT INTO sessions (token_hash, id, expires_at) VALUES ($1, $2, now() + $3::interval)`, [
      tokenHash(token),
      id,
      secs(REST_SESSION_TTL_SECONDS),
    ]);
    return token;
  },

  /** Resolves a bearer, sliding its idle timeout; null when unknown, idle-expired or past the cap. */
  async resolveSessionToken(token: string): Promise<SessionInfo | null> {
    if (!token) return null;
    const row = await one<{ id: string }>(
      `WITH found AS (
         SELECT token_hash, id, iat FROM sessions WHERE token_hash = $1 AND expires_at > now()
       ),
       capped AS (
         DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM found WHERE iat <= now() - $2::interval)
       ),
       slid AS (
         UPDATE sessions SET expires_at = now() + $3::interval
          WHERE token_hash IN (SELECT token_hash FROM found WHERE iat > now() - $2::interval)
            AND expires_at < now() + $4::interval
       )
       SELECT id FROM found WHERE iat > now() - $2::interval`,
      [
        tokenHash(token),
        secs(REST_SESSION_MAX_AGE_SECONDS),
        secs(REST_SESSION_TTL_SECONDS),
        secs(REST_SESSION_TTL_SECONDS - SESSION_SLIDE_AFTER_SECONDS),
      ],
    );
    return row ? { id: row.id } : null;
  },

  /** Ends one session; true when the token named one. */
  async revokeSessionToken(token: string): Promise<boolean> {
    if (!token) return false;
    const res = await q(`DELETE FROM sessions WHERE token_hash = $1`, [tokenHash(token)]);
    return (res.rowCount ?? 0) > 0;
  },

  /** Ends every session and MQTT signing key of a client. */
  async revokeAllSessions(id: string): Promise<void> {
    await q(`DELETE FROM sessions WHERE id = $1`, [id]);
    await q(`DELETE FROM mqtt_session_keys WHERE id = $1`, [id]);
  },

  /** Fixed-window counter; returns the count after this hit. */
  async bumpCounter(key: string, windowSeconds: number): Promise<number> {
    const row = await one<{ n: number }>(
      `INSERT INTO rate_counters (key, n, window_ends_at) VALUES ($1, 1, now() + $2::interval)
       ON CONFLICT (key) DO UPDATE SET
         n = CASE WHEN rate_counters.window_ends_at <= now() THEN 1 ELSE rate_counters.n + 1 END,
         window_ends_at = CASE WHEN rate_counters.window_ends_at <= now()
                               THEN now() + $2::interval ELSE rate_counters.window_ends_at END
       RETURNING n`,
      [key, secs(windowSeconds)],
    );
    return row?.n ?? 1;
  },

  async clearCounter(key: string): Promise<void> {
    await q(`DELETE FROM rate_counters WHERE key = $1`, [key]);
  },
};
