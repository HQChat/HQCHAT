/** Credentials APNs needs before anything can be sent. */
export const APNS_CREDENTIALS = ["APNS_KEY_ID", "APNS_TEAM_ID", "APNS_KEY_P8"] as const;
/** Bundle ids pushes are addressed to; at least one is needed. */
export const APNS_TOPICS = ["APNS_TOPIC_IOS", "APNS_TOPIC_MACOS"] as const;

export type ApnsEnv = Record<string, string | undefined>;

const set = (env: ApnsEnv, k: string) => !!env[k]?.trim();

/** Whether any APNs setting is present, i.e. push was meant to be configured. */
export function apnsIntended(env: ApnsEnv): boolean {
  return [...APNS_CREDENTIALS, ...APNS_TOPICS].some((k) => set(env, k));
}

const PLATFORM: Record<(typeof APNS_TOPICS)[number], string> = {
  APNS_TOPIC_IOS: "iPhone",
  APNS_TOPIC_MACOS: "Mac",
};

/**
 * The settings still missing before every device can be woken. A missing topic
 * is named with the platform it silences.
 */
export function apnsGaps(env: ApnsEnv): string[] {
  const gaps: string[] = APNS_CREDENTIALS.filter((k) => !set(env, k));
  const missing = APNS_TOPICS.filter((k) => !set(env, k));
  if (missing.length === APNS_TOPICS.length) gaps.push(`${APNS_TOPICS.join(" or ")} (the bundle id APNs delivers to)`);
  else for (const k of missing) gaps.push(`${k} (without it, no ${PLATFORM[k]} is ever woken)`);
  return gaps;
}

/** One line describing whether pushes can be sent. */
export function apnsSummary(env: ApnsEnv): string {
  const gaps = apnsGaps(env);
  if (gaps.length) {
    return apnsIntended(env)
      ? `APNs is INCOMPLETE (missing ${gaps.join(", ")}); no device will be woken`
      : "APNs is not configured; no device will be woken";
  }
  const topics = APNS_TOPICS.filter((k) => set(env, k)).map((k) => `${k}=${env[k]}`);
  return `APNs ready (${topics.join(", ")})`;
}

const P8_HEADER = "-----BEGIN PRIVATE KEY-----";
const P8_FOOTER = "-----END PRIVATE KEY-----";

/**
 * Normalises an Apple `.p8` key (PEM, bare base64, or PEM with literal `\n`) to
 * PEM. Null when it is not a PKCS#8 container.
 */
export function normalizeP8(raw: string | undefined): string | null {
  if (!raw) return null;
  const text = raw.replace(/\\n/g, "\n").replace(/\r/g, "").trim();
  if (!text) return null;
  let body: string;
  if (text.includes(P8_HEADER)) {
    const start = text.indexOf(P8_HEADER) + P8_HEADER.length;
    const end = text.indexOf(P8_FOOTER, start);
    body = text.slice(start, end === -1 ? undefined : end);
  } else if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(text)) {
    return null;
  } else {
    body = text;
  }
  body = body.replace(/\s+/g, "");
  if (!body || body.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) return null;
  const der = Buffer.from(body, "base64");
  if (der.length < 48 || der[0] !== 0x30) return null;
  const lines = body.match(/.{1,64}/g) ?? [];
  return `${[P8_HEADER, ...lines, P8_FOOTER].join("\n")}\n`;
}
