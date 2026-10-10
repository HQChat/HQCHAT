import type { GatewayLimits, GatewayStats, RefusalReason } from "./gateway";

/**
 * The gateway's per-address and process-wide bookkeeping: handshakes in
 * progress, established streams, handshake rate windows, the replay cache of
 * client ephemerals, and refusal counts.
 */
export class Admission {
  private halfOpen = 0;
  private established = 0;
  private readonly refused = {} as Record<RefusalReason, number>;
  private readonly handshakesByIp = new Map<string, number>();
  private readonly connectionsByIp = new Map<string, number>();
  private readonly rateByIp = new Map<string, { windowStart: number; count: number }>();
  /** Ephemeral key (hex) → expiry. */
  private readonly seenEphemerals = new Map<string, number>();

  constructor(
    private readonly limits: GatewayLimits,
    private readonly now: () => number,
  ) {}

  /** Why a new connection from `ip` must be refused, or null to admit it. */
  refusalFor(ip: string): RefusalReason | null {
    if (this.halfOpen >= this.limits.maxHalfOpen) return "half-open";
    if ((this.handshakesByIp.get(ip) ?? 0) >= this.limits.perIpHandshakes) return "ip-handshakes";
    if ((this.connectionsByIp.get(ip) ?? 0) >= this.limits.perIpConnections) return "ip-connections";
    if (!this.withinRate(ip)) return "ip-rate";
    return null;
  }

  /** Counts a handshake in progress; the returned function ends it, once. */
  startHandshake(ip: string): () => void {
    this.halfOpen++;
    bump(this.handshakesByIp, ip, 1);
    let open = true;
    return () => {
      if (!open) return;
      open = false;
      this.halfOpen--;
      bump(this.handshakesByIp, ip, -1);
    };
  }

  connectionOpened(ip: string): void {
    this.established++;
    bump(this.connectionsByIp, ip, 1);
  }

  connectionClosed(ip: string): void {
    this.established--;
    bump(this.connectionsByIp, ip, -1);
  }

  countRefusal(reason: RefusalReason): void {
    this.refused[reason] = (this.refused[reason] ?? 0) + 1;
  }

  /**
   * True if this ephemeral is fresh, and records it. Expired entries are swept
   * opportunistically, oldest first (a Map keeps insertion order).
   */
  freshEphemeral(e: Buffer): boolean {
    const t = this.now();
    for (const [k, exp] of this.seenEphemerals) {
      if (exp > t && this.seenEphemerals.size < this.limits.replayCacheMax) break;
      this.seenEphemerals.delete(k);
    }
    const key = e.toString("hex");
    const exp = this.seenEphemerals.get(key);
    if (exp !== undefined && exp > t) return false;
    this.seenEphemerals.set(key, t + this.limits.replayWindowMs);
    return true;
  }

  stats(): GatewayStats {
    return {
      halfOpen: this.halfOpen,
      established: this.established,
      refused: { ...this.refused },
      replayCacheSize: this.seenEphemerals.size,
    };
  }

  /** One-minute window per address; stale windows are swept when the map grows large. */
  private withinRate(ip: string): boolean {
    const t = this.now();
    const r = this.rateByIp.get(ip);
    if (!r || t - r.windowStart >= 60_000) {
      this.rateByIp.set(ip, { windowStart: t, count: 1 });
      if (this.rateByIp.size > 100_000) {
        for (const [k, v] of this.rateByIp) {
          if (t - v.windowStart >= 60_000) this.rateByIp.delete(k);
          else break;
        }
      }
      return true;
    }
    r.count++;
    return r.count <= this.limits.perIpHandshakesPerMinute;
  }
}

function bump(m: Map<string, number>, ip: string, d: number): void {
  const n = (m.get(ip) ?? 0) + d;
  if (n <= 0) m.delete(ip);
  else m.set(ip, n);
}
