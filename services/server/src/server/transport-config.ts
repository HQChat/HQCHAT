import * as fs from "node:fs";

/**
 * What `GET /auth/transport` tells a client about the hqn/1 raw-TCP transport:
 * the gateway's host, port and the public keys to pin. Advertised only when
 * HQN_ENABLED=1, so the gateway can be provisioned before clients use it.
 *
 *   HQN_ENABLED            "1" to advertise the gateway
 *   HQN_PUBLIC_HOST        the gateway's public host (DNS-only, not proxied)
 *   HQN_PUBLIC_PORT        its port
 *   HQN_GATEWAY_KEYS_URL   the gateway's own /keys, so advertised keys always
 *                          match the gateway's; unreachable means not advertised
 *   NOISE_PUBLIC_KEYS      `{ keys: [{ keyId, x25519, hqc }] }` inline, as
 *                          written by noise-gw-keys --public
 *
 * Nothing here is secret. Missing, malformed or unreachable configuration means
 * "no hqn", never an error, so clients fall back to WSS.
 */

export interface HqnPublicKey {
  keyId: number;
  x25519: string;
  hqc: string;
}
export interface TransportInfo {
  hqn: { enabled: boolean; host: string; port: number; keys: HqnPublicKey[] } | null;
}

type Env = NodeJS.ProcessEnv;

function endpoint(env: Env): { host: string; port: number } | null {
  const host = (env.HQN_PUBLIC_HOST || "").trim();
  const port = Number(env.HQN_PUBLIC_PORT || 0);
  if (!host || !/^[A-Za-z0-9.-]+$/.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

/** Only well-formed keys survive; none at all means no hqn. */
export function validKeys(parsed: unknown): HqnPublicKey[] {
  const raw = (parsed as { keys?: unknown })?.keys;
  if (!Array.isArray(raw)) return [];
  return raw
    .map((entry) => {
      const k = (entry ?? {}) as Record<string, unknown>;
      const text = (v: unknown) => (typeof v === "string" ? v : "");
      return { keyId: Number(k.keyId), x25519: text(k.x25519), hqc: text(k.hqc) };
    })
    .filter(
      (k) =>
        Number.isInteger(k.keyId) &&
        k.keyId >= 0 &&
        k.keyId <= 255 &&
        Buffer.from(k.x25519, "base64").length === 32 &&
        Buffer.from(k.hqc, "base64").length === 7237,
    );
}

function staticKeys(env: Env): HqnPublicKey[] {
  try {
    if (env.NOISE_PUBLIC_KEYS) return validKeys(JSON.parse(env.NOISE_PUBLIC_KEYS));
    if (env.NOISE_PUBLIC_KEYS_FILE) return validKeys(JSON.parse(fs.readFileSync(env.NOISE_PUBLIC_KEYS_FILE, "utf8")));
  } catch {
    /* malformed → none */
  }
  return [];
}

/** The answer from static configuration only (no gateway fetch). */
export function transportInfo(env: Env = process.env): TransportInfo {
  const ep = endpoint(env);
  if (!ep || env.HQN_ENABLED !== "1") return { hqn: null };
  const keys = staticKeys(env);
  return keys.length ? { hqn: { enabled: true, ...ep, keys } } : { hqn: null };
}

const GOOD_FOR_MS = 60_000;
const BAD_FOR_MS = 10_000;
const FETCH_TIMEOUT_MS = 1_500;
let cache: { url: string; keys: HqnPublicKey[]; until: number } | null = null;

/** Clears the cached gateway keys. */
export function __resetGatewayKeyCache(): void {
  cache = null;
}

async function gatewayKeys(url: string, now: number, fetchImpl: typeof fetch): Promise<HqnPublicKey[]> {
  if (cache && cache.url === url && cache.until > now) return cache.keys;
  let keys: HqnPublicKey[] = [];
  try {
    const r = await fetchImpl(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (r.ok) keys = validKeys(await r.json());
  } catch {
    /* unreachable → none */
  }
  cache = { url, keys, until: now + (keys.length ? GOOD_FOR_MS : BAD_FOR_MS) };
  return keys;
}

/**
 * What the route answers. With `HQN_GATEWAY_KEYS_URL` set, the keys come from
 * the gateway (cached a minute; a failure is retried after ten seconds), so an
 * unreachable gateway is simply not advertised. Otherwise static config.
 */
export async function resolveTransportInfo(
  env: Env = process.env,
  opts: { now?: number; fetchImpl?: typeof fetch } = {},
): Promise<TransportInfo> {
  const ep = endpoint(env);
  if (!ep || env.HQN_ENABLED !== "1") return { hqn: null };
  const url = (env.HQN_GATEWAY_KEYS_URL || "").trim();
  if (!url) return transportInfo(env);
  const keys = await gatewayKeys(url, opts.now ?? Date.now(), opts.fetchImpl ?? fetch);
  return keys.length ? { hqn: { enabled: true, ...ep, keys } } : { hqn: null };
}
