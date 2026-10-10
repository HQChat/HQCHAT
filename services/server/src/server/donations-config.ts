/** Comma-separated Stripe price ids of the monthly donation tiers, in display order. */
export const DONATION_TIERS_VAR = "STRIPE_DONATION_PRICE_IDS";
/** Stripe price id of the one-time donation. */
export const DONATION_ONCE_VAR = "STRIPE_DONATION_ONCE_PRICE_ID";

export type DonationEnv = Record<string, string | undefined>;

/** The prices the donate buttons charge. */
export interface DonationPrices {
  tiers: string[];
  once: string;
}

const isPriceId = (v: string) => v.startsWith("price_");

/** Reads the configured prices; anything that is not a Stripe price id is ignored. */
export function resolvePrices(env: DonationEnv): DonationPrices {
  const tiers = (env[DONATION_TIERS_VAR] || "")
    .split(",")
    .map((s) => s.trim())
    .filter(isPriceId);
  const once = env[DONATION_ONCE_VAR]?.trim() || "";
  return { tiers, once: isPriceId(once) ? once : "" };
}

/** The variables that resolve to nothing. */
export function donationGaps(p: DonationPrices): string[] {
  const gaps: string[] = [];
  if (p.tiers.length === 0) gaps.push(DONATION_TIERS_VAR);
  if (!p.once) gaps.push(DONATION_ONCE_VAR);
  return gaps;
}

/** True when no donation can be charged at all. */
export function donationsDead(p: DonationPrices): boolean {
  return donationGaps(p).length === 2;
}

/** One line describing what can be charged. */
export function donationSummary(p: DonationPrices): string {
  const gaps = donationGaps(p);
  if (gaps.length === 0) return `donations ready (${p.tiers.length} monthly tier(s) + one-time)`;
  return `donations are missing ${gaps.join(" and ")}; those buttons refuse`;
}
