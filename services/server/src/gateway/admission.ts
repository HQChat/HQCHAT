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
  private readonly handshakesByPrefix = new Map<string, number>();
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
    if ((this.handshakesByPrefix.get(addressPrefix(ip)) ?? 0) >= this.limits.perPrefixHandshakes) {
      return "prefix-handshakes";
    }
    if ((this.connectionsByIp.get(ip) ?? 0) >= this.limits.perIpConnections) return "ip-connections";
    if (!this.withinRate(ip)) return "ip-rate";
    return null;
  }

  /** Counts a handshake in progress; the returned function ends it, once. */
  startHandshake(ip: string): () => void {
    const prefix = addressPrefix(ip);
    this.halfOpen++;
    bump(this.handshakesByIp, ip, 1);
    bump(this.handshakesByPrefix, prefix, 1);
    let open = true;
    return () => {
      if (!open) return;
      open = false;
      this.halfOpen--;
      bump(this.handshakesByIp, ip, -1);
      bump(this.handshakesByPrefix, prefix, -1);
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

/**
 * The network an address belongs to for the per-prefix cap: its /24 for IPv4
 * (including IPv4-mapped IPv6), its /56 for IPv6. Anything unparseable is its
 * own prefix.
 */
export function addressPrefix(ip: string): string {
  const v4 = ip.match(/^(?:::ffff:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/i);
  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}.0/24`;
  const addr = ip.split("%")[0]!.toLowerCase();
  const halves = addr.split("::");
  if (halves.length > 2) return ip;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return ip;
  const groups = [...head, ...Array(missing).fill("0"), ...tail];
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return ip;
  const hex = groups.map((g) => g.padStart(4, "0")).join("");
  return `${hex.slice(0, 14)}/56`;
}

function bump(m: Map<string, number>, ip: string, d: number): void {
  const n = (m.get(ip) ?? 0) + d;
  if (n <= 0) m.delete(ip);
  else m.set(ip, n);
}
