/**
 * One synthetic user ("sim"): an ordinary account on the Rust core that acts
 * like a person, so the hourly report measures what a phone gets. It pings
 * other sims and times the echo, echoes back exactly whatever anyone sends
 * it, answers invites with a coin flip, makes and drops friends among the
 * sims, and now and then loses its network so messages wait in the broker's
 * offline queue.
 *
 * Real users' text is held only long enough to send it back: never logged,
 * never stored, never in a report. Reports carry counts and milliseconds.
 */

import * as fs from "node:fs";
import type { CoreEffect, CoreInvite, CoreMessage } from "../common/core";
import type { CoreClient } from "../common/core-client";
import { logger } from "../common/logger";
import { Tally } from "./stats";

/** Mean wait between two pings from one sim, and its bounds. */
const PING_MEAN_MS = 120_000;
const PING_MIN_MS = 30_000;
const PING_MAX_MS = 300_000;
/** A ping without its echo after this long counts as lost; one after LATE_MS, as late. */
export const LOST_MS = 5 * 60_000;
export const LATE_MS = 30_000;
/** Own pings are recognised this long, so a late copy is never echoed back into a loop. */
const OWN_MEMORY_MS = 24 * 3_600_000;
/** Echoes to one peer within a minute; beyond it, another echo bot would loop with us. */
export const ECHO_CAP_PER_MIN = 20;
/** How long a sim takes to answer an invite. */
const DECIDE_MIN_MS = 10_000;
const DECIDE_MAX_MS = 10 * 60_000;
/** The friendship churn: once an hour, a few invites and, rarely, a removal. */
const SOCIAL_MS = 3_600_000;
const INVITES_PER_ROUND = 2;
const REMOVE_CHANCE = 1 / 24;
/** A sim that was declined (or dropped) is invited again only after this. */
export const REINVITE_AFTER_MS = 3_600_000;
/** Being away: how often, and for how long. */
const AWAY_MEAN_MS = 20 * 60_000;
const AWAY_MIN_MS = 60_000;
const AWAY_MAX_MS = 10 * 60_000;
/** A failed message is sent again this often, this many times. */
const RETRY_MS = 30_000;
const MAX_RETRIES = 3;
const SWEEP_MS = 60_000;

export type Transport = "hqn" | "wss";
type Kind = "ping" | "echoSim" | "echoReal";

/** The client calls a sim makes; a CoreClient, or a fake in the tests. */
export type SimClient = Pick<CoreClient, "start" | "send" | "run" | "onMessage" | "onEffect" | "setReachable"> & {
  engine: Pick<
    CoreClient["engine"],
    "friends" | "invites" | "sentInvites" | "invite" | "accept" | "cancel" | "remove" | "retry" | "setUsername"
  >;
};

export interface Env {
  rng: () => number;
  now: () => number;
  later: (ms: number, fn: () => void) => void;
}

export const realEnv: Env = {
  rng: Math.random,
  now: Date.now,
  later: (ms, fn) => {
    setTimeout(fn, ms);
  },
};

interface Declined {
  username: string;
  /** The sim that declined: another one invites back. */
  by: string;
  declinedAt: number;
  invitedAt?: number;
}

/** A real user may be invited back once their invite has waited this long… */
const REAL_REINVITE_AFTER_MS = 3_600_000;
/** …at most once in this long… */
export const REAL_REINVITE_EVERY_MS = 7 * 24 * 3_600_000;
/** …by a sim's social round with this chance, so the fleet asks within hours, not at once. */
const REAL_REINVITE_CHANCE = 0.02;
const REAL_FORGET_MS = 30 * 24 * 3_600_000;

/**
 * Real users a sim declined, shared by the fleet so a different sim may invite
 * them back. Only users who invited first are here. Kept on the node (the
 * 7-day limit has to survive a restart), never in a report.
 */
export class RealUsers {
  private readonly users: Map<string, Declined>;

  constructor(private readonly file: string | null) {
    this.users = new Map(
      file && fs.existsSync(file)
        ? Object.entries(JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, Declined>)
        : [],
    );
  }

  declined(id: string, username: string, by: string, now: number): void {
    const was = this.users.get(id);
    this.users.set(id, { username, by, declinedAt: now, ...(was?.invitedAt ? { invitedAt: was.invitedAt } : {}) });
    this.save();
  }

  /** One user `by` may invite back now, marked as invited; null for none. */
  pick(
    by: string,
    now: number,
    rng: () => number,
    skip: (id: string) => boolean,
  ): { id: string; username: string } | null {
    for (const [id, u] of this.users) {
      if (now - u.declinedAt > REAL_FORGET_MS) {
        this.users.delete(id);
        continue;
      }
      if (u.by === by || skip(id) || now - u.declinedAt < REAL_REINVITE_AFTER_MS) continue;
      if (u.invitedAt !== undefined && now - u.invitedAt < REAL_REINVITE_EVERY_MS) continue;
      if (rng() >= REAL_REINVITE_CHANCE) continue;
      u.invitedAt = now;
      this.save();
      return { id, username: u.username };
    }
    return null;
  }

  private save(): void {
    if (!this.file) return;
    fs.writeFileSync(this.file, JSON.stringify(Object.fromEntries(this.users)), { mode: 0o600 });
  }
}

/** What every sim in the process shares. */
export interface Fleet {
  /** Each sim's id → its handle. */
  sims: Map<string, string>;
  /** The helper bot: befriended to every account, and never echoed. */
  botId: string | null;
  realUsers: RealUsers;
}

interface Ping {
  peer: string;
  text: string;
  at: number;
  bucket: string;
  state: "open" | "lost" | "done";
}

interface Outgoing {
  kind: Kind;
  at: number;
  seen: Set<string>;
  retries: number;
}

const PING = /^ping (\S+)·(\d+)·[0-9a-f]+$/;

/**
 * A core reason as a counter key: the words before any detail (`:` or `(`),
 * leaving out every word with a digit in it, so no peer id, topic or error
 * value reaches a report. "could not seal for 3fa9…: …" → "could_not_seal_for".
 */
export function reasonKey(reason: string | undefined): string {
  const words = (reason ?? "")
    .split(/[:(]/)[0]!
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w && !/\d/.test(w))
    .map((w) => w.replace(/[^a-z]/g, ""))
    .filter(Boolean);
  return words.join("_").slice(0, 48) || "other";
}

export class Sim {
  readonly tally = new Tally();
  private seq = 0;
  private readonly pings = new Map<number, Ping>();
  private readonly outgoing = new Map<string, Outgoing>();
  private readonly echoes = new Map<string, number[]>();
  /** Invites being decided, by inviter, with when the decision was taken. */
  private readonly deciding = new Map<string, number>();
  private readonly lastInvited = new Map<string, number>();
  private readonly realThisWindow = new Set<string>();
  private claimed = false;

  private away = false;
  private awaySince = 0;
  private awayMs = 0;
  private connectedSince: number | null = null;
  private connectedMs = 0;
  private reconnectFrom: { at: number; kind: "start" | "drop" | "away" } | null = null;
  private windowStart: number;

  constructor(
    private readonly client: SimClient,
    readonly handle: string,
    private transport: Transport,
    private readonly fleet: Fleet,
    private readonly env: Env = realEnv,
  ) {
    this.windowStart = env.now();
    client.onMessage((m) => this.onMessage(m));
    client.onEffect((e) => this.onEffect(e));
  }

  start(): void {
    this.reconnectFrom = { at: this.env.now(), kind: "start" };
    this.client.start();
    this.env.later(this.pingWait(), () => this.pingLoop());
    this.env.later(SWEEP_MS, () => this.sweepLoop());
    this.env.later(this.uniform(10_000, 120_000), () => this.socialLoop());
    this.env.later(this.exp(AWAY_MEAN_MS, AWAY_MIN_MS, 4 * AWAY_MEAN_MS), () => this.goAway());
  }

  // ── messages ──

  onMessage(m: CoreMessage): void {
    if (m.peer === this.fleet.botId) {
      this.tally.count("fromBot");
      return;
    }
    const own = PING.exec(m.text);
    if (own && own[1] === this.handle) {
      this.ownPingBack(Number(own[2]), m.peer, m.text);
      return;
    }
    this.echo(m.peer, m.text);
  }

  private ownPingBack(seq: number, peer: string, text: string): void {
    const p = this.pings.get(seq);
    if (!p || p.peer !== peer) {
      this.tally.count("unknownOwn");
      return;
    }
    if (p.text !== text) {
      this.tally.count("corrupted");
      return;
    }
    if (p.state === "done") {
      this.tally.count("duplicates");
      return;
    }
    const rtt = this.env.now() - p.at;
    this.tally.count("echoesBack");
    this.tally.sample(p.bucket, rtt);
    if (rtt > LATE_MS) this.tally.count("late");
    if (p.state === "lost") this.tally.count("lateAfterLost");
    p.state = "done";
  }

  private echo(peer: string, text: string): void {
    const real = !this.fleet.sims.has(peer);
    this.tally.count(real ? "fromReal" : "fromSims");
    const now = this.env.now();
    const recent = (this.echoes.get(peer) ?? []).filter((t) => now - t < 60_000);
    if (recent.length >= ECHO_CAP_PER_MIN) {
      this.echoes.set(peer, recent);
      this.tally.count("echoesCapped");
      return;
    }
    recent.push(now);
    this.echoes.set(peer, recent);
    if (real) this.realThisWindow.add(peer);
    this.sendTracked(peer, text, real ? "echoReal" : "echoSim");
  }

  ping(): void {
    if (this.away) {
      this.tally.count("pingsWhileAway");
      return;
    }
    const friends = this.client.engine.friends().filter((f) => this.fleet.sims.has(f.id) && !f.blockedAt);
    const friend = this.pick(friends);
    if (!friend) {
      this.tally.count("pingsNoFriend");
      return;
    }
    const seq = ++this.seq;
    const nonce = Math.floor(this.env.rng() * 2 ** 32)
      .toString(16)
      .padStart(8, "0");
    const text = `ping ${this.handle}·${seq}·${nonce}`;
    if (!this.sendTracked(friend.id, text, "ping")) return;
    const bucket = `rtt.${this.transport}.${friend.online ? "online" : "offline"}`;
    this.pings.set(seq, { peer: friend.id, text, at: this.env.now(), bucket, state: "open" });
    this.tally.count("pingsSent");
  }

  private sendTracked(peer: string, text: string, kind: Kind): boolean {
    try {
      const id = this.client.send(peer, text);
      this.outgoing.set(id, { kind, at: this.env.now(), seen: new Set(), retries: 0 });
      this.tally.count(`sent.${kind}`);
      return true;
    } catch (e) {
      this.tally.count(`sendRefused.${kind}`);
      logger.warn(`[sim ${this.handle}] a ${kind} was refused: ${(e as Error).message}`);
      return false;
    }
  }

  private onStatus(msgId: string, state: string): void {
    const o = this.outgoing.get(msgId);
    if (!o || o.seen.has(state)) return;
    o.seen.add(state);
    this.tally.count(`delivery.${o.kind}.${state}`);
    if (state === "sent" || state === "delivered") this.tally.sample(`${state}.${o.kind}`, this.env.now() - o.at);
    if (state !== "failed") return;
    if (o.retries >= MAX_RETRIES) {
      this.tally.count(`delivery.${o.kind}.gaveUp`);
      return;
    }
    o.retries++;
    this.env.later(RETRY_MS, () => {
      o.seen.delete("failed");
      o.seen.delete("sending");
      this.client.run(() => this.client.engine.retry(msgId, this.env.now()));
    });
  }

  /** Marks pings lost and forgets what is too old to matter. */
  sweep(): void {
    const now = this.env.now();
    for (const [seq, p] of this.pings) {
      if (p.state === "open" && now - p.at > LOST_MS) {
        p.state = "lost";
        this.tally.count("lost");
      }
      if (now - p.at > OWN_MEMORY_MS) this.pings.delete(seq);
    }
    for (const [id, o] of this.outgoing) if (now - o.at > OWN_MEMORY_MS) this.outgoing.delete(id);
    for (const [peer, times] of this.echoes) if (times.every((t) => now - t >= 60_000)) this.echoes.delete(peer);
  }

  // ── friends ──

  private onInvites(): void {
    const now = this.env.now();
    const invites = this.client.engine.invites();
    const open = new Set(invites.map((i) => i.id));
    // An inviter whose invite is gone (taken, or withdrawn) may invite again later.
    for (const [id, at] of this.deciding) if (!open.has(id) && now - at > 60_000) this.deciding.delete(id);
    for (const invite of invites) {
      if (this.deciding.has(invite.id)) continue;
      this.deciding.set(invite.id, Number.POSITIVE_INFINITY);
      this.tally.count(this.fleet.sims.has(invite.id) ? "invitesFrom.sims" : "invitesFrom.real");
      this.env.later(this.uniform(DECIDE_MIN_MS, DECIDE_MAX_MS), () => this.decide(invite));
    }
  }

  /** Accepts half the invites and declines the rest. */
  decide(invite: CoreInvite): void {
    this.deciding.set(invite.id, this.env.now());
    if (!this.client.engine.invites().some((i) => i.id === invite.id)) {
      this.tally.count("invitesWithdrawn");
      return;
    }
    const who = this.fleet.sims.has(invite.id) ? "sims" : "real";
    if (this.env.rng() < 0.5) {
      this.client.run(() => this.client.engine.accept(invite.id));
      this.tally.count(`accepted.${who}`);
      return;
    }
    // Declining is a cancel: POST /friends/cancel takes back an invite either way; remove is for friends.
    this.client.run(() => this.client.engine.cancel(invite.id));
    this.tally.count(`declined.${who}`);
    if (who === "real") this.fleet.realUsers.declined(invite.id, invite.username, this.handle, this.env.now());
  }

  /** One round of friendship churn: invite a few sims, rarely drop one, maybe invite back a real user. */
  social(): void {
    const now = this.env.now();
    const engine = this.client.engine;
    const friends = engine.friends();
    const taken = new Set([
      ...friends.map((f) => f.id),
      ...engine.sentInvites().map((s) => s.to),
      ...engine.invites().map((i) => i.id),
    ]);
    const candidates = [...this.fleet.sims].filter(
      ([id, handle]) =>
        handle !== this.handle &&
        !taken.has(id) &&
        !taken.has(handle) &&
        now - (this.lastInvited.get(id) ?? Number.NEGATIVE_INFINITY) >= REINVITE_AFTER_MS,
    );
    for (let i = 0; i < INVITES_PER_ROUND && candidates.length > 0; i++) {
      const [id, handle] = candidates.splice(Math.floor(this.env.rng() * candidates.length), 1)[0]!;
      this.lastInvited.set(id, now);
      this.client.run(() => engine.invite(handle));
      this.tally.count("invitesSent.sims");
    }
    if (this.env.rng() < REMOVE_CHANCE) {
      const friend = this.pick(friends.filter((f) => this.fleet.sims.has(f.id)));
      if (friend) {
        this.lastInvited.set(friend.id, now);
        this.client.run(() => engine.remove(friend.id));
        this.tally.count("friendsRemoved");
      }
    }
    const back = this.fleet.realUsers.pick(this.handle, now, this.env.rng, (id) => taken.has(id));
    if (back) {
      this.client.run(() => engine.invite(back.username));
      this.tally.count("invitesSent.real");
    }
  }

  // ── connection ──

  private onEffect(e: CoreEffect): void {
    switch (e.kind) {
      case "messageStatus":
        this.onStatus(e.msgId!, e.state!);
        return;
      case "invitesChanged":
        this.onInvites();
        return;
      case "open":
        // While away every dial fails on purpose (and may fall back to WSS): not the sim's transport.
        if (this.away) return;
        this.transport = e.transport === "tcp" ? "hqn" : "wss";
        this.tally.count(`dials.${this.transport}`);
        return;
      case "connection":
        this.onConnection(e.state!);
        return;
      case "actionFailed":
        this.tally.count(`failed.${e.action}.${e.status}`);
        return;
      case "dropped":
      case "storageFailed":
        this.tally.count(`${e.kind}.${reasonKey(e.reason)}`);
        return;
      default:
        return;
    }
  }

  private onConnection(state: string): void {
    const now = this.env.now();
    if (state === "connected") {
      if (this.connectedSince !== null) return;
      this.connectedSince = now;
      this.tally.count("connects");
      if (this.reconnectFrom) this.tally.sample(`connect.${this.reconnectFrom.kind}`, now - this.reconnectFrom.at);
      this.reconnectFrom = null;
      if (!this.claimed) {
        this.claimed = true;
        this.client.run(() => this.client.engine.setUsername(this.handle));
      }
      return;
    }
    if (this.connectedSince === null) return;
    this.connectedMs += now - this.connectedSince;
    this.connectedSince = null;
    if (!this.away) {
      this.tally.count("drops");
      this.reconnectFrom = { at: now, kind: "drop" };
    }
  }

  private goAway(): void {
    this.away = true;
    this.awaySince = this.env.now();
    this.tally.count("aways");
    this.client.setReachable(false);
    this.env.later(this.uniform(AWAY_MIN_MS, AWAY_MAX_MS), () => this.comeBack());
  }

  private comeBack(): void {
    const now = this.env.now();
    this.awayMs += now - this.awaySince;
    this.away = false;
    this.reconnectFrom = { at: now, kind: "away" };
    this.client.setReachable(true);
    this.env.later(this.exp(AWAY_MEAN_MS, AWAY_MIN_MS, 4 * AWAY_MEAN_MS), () => this.goAway());
  }

  /** Closes the window: its raw tally and the time base for uptime. */
  roll(): { raw: ReturnType<Tally["take"]>; windowMs: number; connectedMs: number; presentMs: number } {
    const now = this.env.now();
    if (this.connectedSince !== null) {
      this.connectedMs += now - this.connectedSince;
      this.connectedSince = now;
    }
    if (this.away) {
      this.awayMs += now - this.awaySince;
      this.awaySince = now;
    }
    this.tally.count("realUsers", this.realThisWindow.size);
    this.realThisWindow.clear();
    const windowMs = now - this.windowStart;
    const out = { raw: this.tally.take(), windowMs, connectedMs: this.connectedMs, presentMs: windowMs - this.awayMs };
    this.windowStart = now;
    this.connectedMs = 0;
    this.awayMs = 0;
    return out;
  }

  // ── timing ──

  private pingLoop(): void {
    this.ping();
    this.env.later(this.pingWait(), () => this.pingLoop());
  }

  private sweepLoop(): void {
    this.sweep();
    this.env.later(SWEEP_MS, () => this.sweepLoop());
  }

  private socialLoop(): void {
    this.social();
    this.env.later(SOCIAL_MS, () => this.socialLoop());
  }

  private pingWait(): number {
    return this.exp(PING_MEAN_MS, PING_MIN_MS, PING_MAX_MS);
  }

  private exp(mean: number, min: number, max: number): number {
    return Math.min(max, Math.max(min, -mean * Math.log(1 - this.env.rng())));
  }

  private uniform(min: number, max: number): number {
    return min + this.env.rng() * (max - min);
  }

  private pick<T>(list: readonly T[]): T | undefined {
    return list[Math.floor(this.env.rng() * list.length)];
  }
}
