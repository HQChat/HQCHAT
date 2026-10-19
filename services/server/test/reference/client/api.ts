import type { TransportInfo } from "../../../src/server/transport-config";
import { isPeerId, keyMatchesId } from "../protocol/identity";
import { TOPIC_ID } from "../protocol/topics";
import type { Auth } from "./auth";
import { requestJson } from "./http";

/** A friend as `/friends` lists them, with the friendship's topic ids. */
export interface Friend {
  id: string;
  username: string;
  convoId: string;
  handshakeId: string;
}

/** A pending invite to this client. */
export interface Invite {
  id: string;
  username: string;
}

/** A claimed prekey bundle: hex public keys. */
export interface PrekeyClaim {
  medium: string;
  oneTime: { id: number; prekey: string } | null;
}

/** What `/report` takes besides the reporter's session. */
export interface ReportInput {
  conversation: string;
  peer: string;
  category: string;
  note?: string;
  excerpt?: string;
  frame?: Buffer;
  messageId?: string;
}

/**
 * The REST API, typed. Methods throw ApiError on a non-2xx answer; reads that
 * the server answers in an unexpected shape throw rather than guess.
 */
export class Api {
  constructor(
    private readonly baseUrl: string,
    private readonly auth: Auth,
  ) {}

  private call<T = Record<string, unknown>>(method: string, path: string, body?: unknown): Promise<T> {
    return requestJson<T>(`${this.baseUrl}${path}`, {
      method,
      bearer: this.auth.bearer,
      ...(body !== undefined ? { body } : {}),
    });
  }

  /** `{ ok, version, broker }` from the server's health endpoint. */
  health(): Promise<{ ok: boolean; version: string; broker: string[] }> {
    return requestJson(`${this.baseUrl}/health`);
  }

  /** The hqn/1 gateway, when the server advertises one. */
  transport(): Promise<TransportInfo> {
    return requestJson(`${this.baseUrl}/auth/transport`);
  }

  async setUsername(username: string): Promise<void> {
    await this.call("POST", "/username", { username });
  }

  /** The id registered under a username, or null. */
  async lookup(username: string): Promise<string | null> {
    const r = await requestJson<{ id: string | null }>(
      `${this.baseUrl}/users?username=${encodeURIComponent(username)}`,
    );
    return r.id;
  }

  /** Invites `to`, a username or client id. */
  async invite(to: string): Promise<void> {
    await this.call("POST", "/friends/invite", { to });
  }

  async invites(): Promise<Invite[]> {
    const r = await this.call<{ invites?: Array<{ id?: unknown; username?: unknown }> }>("GET", "/friends/invites");
    if (!Array.isArray(r.invites)) throw new Error("/friends/invites returned no list");
    return r.invites
      .map((i) => ({ id: String(i.id ?? "").toLowerCase(), username: String(i.username ?? "") }))
      .filter((i) => isPeerId(i.id));
  }

  /** Accepts the invite `from` sent. */
  async accept(from: string): Promise<void> {
    await this.call("POST", "/friends/accept", { from });
  }

  /** Withdraws an invite to `peer`, or declines one from them. */
  async cancel(peer: string): Promise<void> {
    await this.call("POST", "/friends/cancel", { peer });
  }

  /** Ends the friendship with `peer`. */
  async remove(peer: string): Promise<void> {
    await this.call("POST", "/friends/remove", { peer });
  }

  async block(peer: string): Promise<void> {
    await this.call("POST", "/friends/block", { peer });
  }

  async unblock(peer: string): Promise<void> {
    await this.call("POST", "/friends/unblock", { peer });
  }

  async blocked(): Promise<string[]> {
    const r = await this.call<{ blocked?: string[] }>("GET", "/friends/blocked");
    return r.blocked ?? [];
  }

  /** Every friend with well-formed topic ids; throws when the answer is not a list. */
  async friends(): Promise<Friend[]> {
    const r = await this.call<{ friends?: unknown }>("GET", "/friends");
    if (!Array.isArray(r.friends)) throw new Error("/friends returned no list");
    const out: Friend[] = [];
    for (const row of r.friends as Array<Record<string, unknown>>) {
      const f = {
        id: String(row.id ?? "").toLowerCase(),
        username: String(row.username ?? ""),
        convoId: String(row.convo_id ?? ""),
        handshakeId: String(row.handshake_id ?? ""),
      };
      if (isPeerId(f.id) && TOPIC_ID.test(f.convoId) && TOPIC_ID.test(f.handshakeId)) out.push(f);
    }
    return out;
  }

  /** A peer's identity key, verified against their id; throws when it does not match. */
  async peerKey(id: string): Promise<Buffer> {
    const r = await requestJson<{ publicKey?: string }>(`${this.baseUrl}/peer/${id}/key`);
    const hex = String(r.publicKey ?? "").toLowerCase();
    if (!keyMatchesId(hex, id)) throw new Error(`the key served for ${id.slice(0, 12)}… does not hash to that id`);
    return Buffer.from(hex, "hex");
  }

  /** Claims a friend's prekeys (consuming one one-time key); 404 NO_PREKEYS when none are published. */
  claimPrekeys(peer: string): Promise<PrekeyClaim> {
    return this.call<PrekeyClaim>("POST", "/prekeys/claim", { peer });
  }

  /** Replaces the medium-term prekey and adds one-time prekeys. */
  async publishPrekeys(medium: Buffer, oneTime: Array<{ id: number; pk: Buffer }>): Promise<void> {
    await this.call("POST", "/prekeys", {
      medium: medium.toString("hex"),
      oneTime: oneTime.map((k) => ({ id: k.id, prekey: k.pk.toString("hex") })),
    });
  }

  /** One-time prekeys still unclaimed on the server. */
  async prekeyCount(): Promise<number> {
    const r = await this.call<{ remaining?: number }>("GET", "/prekeys/count");
    return Number(r.remaining ?? 0);
  }

  /** Files a report about a conversation; returns its id. */
  async report(r: ReportInput): Promise<string> {
    const body = await this.call<{ id: string }>("POST", "/report", {
      ...r,
      ...(r.frame ? { frame: r.frame.toString("base64") } : {}),
    });
    return body.id;
  }

  async registerPushToken(platform: "ios" | "macos", environment: "production" | "sandbox", token: string) {
    await this.call("POST", "/push/token", { platform, environment, token });
  }

  /** Deletes the account and everything stored about it. */
  async deleteAccount(): Promise<void> {
    await this.call("POST", "/account/delete");
  }
}
