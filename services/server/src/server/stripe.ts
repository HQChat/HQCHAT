/**
 * Stripe Checkout for donations. A payment grants nothing and is not looked up
 * again; the only data kept is an optional display name for the supporters
 * page. No email address reaches this server.
 */

import { logger } from "@hqchat/common/logger";
import Stripe from "stripe";
import { resolvePrices } from "./donations-config";

let _stripe: Stripe | null = null;
/** The Stripe client, created on first use so the server boots without a key. */
function stripeClient(): Stripe {
  if (_stripe) return _stripe;
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    throw new Error("STRIPE_SECRET_KEY is required when DONATIONS_ENABLED=1");
  }
  _stripe = new Stripe(key, { apiVersion: "2025-02-24.acacia" });
  return _stripe;
}

const PRICES = resolvePrices(process.env);
const DONATION_PRICE_IDS = PRICES.tiers;

/** Whether recurring tiers can be offered at all. */
export function monthlyTiersAvailable(): boolean {
  return DONATION_PRICE_IDS.length > 0;
}

/** The configured tier price ids, in the order they should be displayed. */
export function donationPriceIds(): readonly string[] {
  return DONATION_PRICE_IDS;
}

/** How many monthly tiers are offered; the site's `TIERS` labels must match. */
export function tierCount(): number {
  return DONATION_PRICE_IDS.length;
}

const ONCE_PRICE_ID = PRICES.once;

/** Whether the one-time donation can be offered. */
export function oneTimeAvailable(): boolean {
  return ONCE_PRICE_ID.length > 0;
}

/** Checkout custom field holding the optional supporters-page name. */
export const DISPLAY_NAME_FIELD_KEY = "display_name";

const displayNameField: Stripe.Checkout.SessionCreateParams.CustomField = {
  key: DISPLAY_NAME_FIELD_KEY,
  type: "text",
  optional: true,
  label: { type: "custom", custom: "Name for the supporters page (optional)" },
  text: { maximum_length: 60 },
};

/**
 * Which donation the visitor picked. A monthly tier is an index into the
 * configured tiers, so the site never carries price ids and a request cannot
 * name an unlisted price.
 */
export type DonationChoice = { kind: "monthly"; index: number } | { kind: "once" };

/**
 * Checkout session parameters for a choice. Subscription and payment modes
 * accept different parameter sets; test/unit/checkout.test.ts guards both.
 */
export function checkoutSessionParams(baseUrl: string, choice: DonationChoice): Stripe.Checkout.SessionCreateParams {
  const common = {
    success_url: `${baseUrl}/donate/thanks`,
    cancel_url: `${baseUrl}/donate/cancelled`,
    custom_fields: [displayNameField],
  };

  if (choice.kind === "monthly") {
    const priceId = DONATION_PRICE_IDS[choice.index];
    if (!Number.isInteger(choice.index) || !priceId) {
      throw new Error(`no donation tier at index ${choice.index}`);
    }
    return {
      ...common,
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
    };
  }

  if (!ONCE_PRICE_ID) throw new Error("one-time donations are not configured");
  return {
    ...common,
    mode: "payment",
    line_items: [{ price: ONCE_PRICE_ID, quantity: 1 }],
  };
}

/** The part of a Checkout Session that carries the custom fields typed at checkout. */
export interface CheckoutCustomFields {
  custom_fields?: Array<{ key: string; text?: { value?: string | null } | null }> | null;
}

/** The display name typed at checkout, trimmed to 60 characters, or null. */
export function displayNameFromSession(session: CheckoutCustomFields): string | null {
  const field = (session.custom_fields ?? []).find((f) => f.key === DISPLAY_NAME_FIELD_KEY);
  const value = field?.text?.value?.trim() ?? "";
  return value.length > 0 ? value.slice(0, 60) : null;
}

/** The part of a webhook event that decides whether it names a supporter. */
export interface SupporterEvent {
  type: string;
  data: { object: CheckoutCustomFields & { payment_status?: string | null } };
}

/**
 * The name to put on the supporters page for a webhook event, or null. Only a
 * paid checkout names anyone: a completed session whose payment is still
 * pending (an asynchronous method) is named when Stripe reports it succeeded,
 * and never if it fails.
 */
export function supporterFromEvent(event: SupporterEvent): string | null {
  const paid =
    (event.type === "checkout.session.completed" || event.type === "checkout.session.async_payment_succeeded") &&
    event.data.object.payment_status === "paid";
  return paid ? displayNameFromSession(event.data.object) : null;
}

export interface TierLabel {
  priceId: string;
  label: string;
}

/** Reads each configured tier's label from Stripe; `complete` is false when any read failed. */
async function loadTierLabels(): Promise<{ labels: TierLabel[]; complete: boolean }> {
  const out: TierLabel[] = [];
  let complete = true;
  for (const priceId of DONATION_PRICE_IDS) {
    try {
      const price = await stripeClient().prices.retrieve(priceId);
      const amount = typeof price.unit_amount === "number" ? price.unit_amount / 100 : null;
      const symbols: Record<string, string> = { eur: "€", usd: "$" };
      const symbol = symbols[price.currency] ?? "";
      out.push({
        priceId,
        label: amount === null ? "choose" : `${symbol}${amount.toFixed(0)} / month`,
      });
    } catch (e) {
      complete = false;
      logger.warn(`[stripe] could not read price ${priceId}: ${(e as Error).message}`);
      out.push({ priceId, label: "monthly" });
    }
  }
  return { labels: out, complete };
}

/**
 * A value loaded at most once per `ttlMs` (`failedTtlMs` when the load was
 * incomplete), with concurrent callers sharing one load.
 */
export function labelCache(
  load: () => Promise<{ labels: TierLabel[]; complete: boolean }>,
  opts: { ttlMs: number; failedTtlMs: number; now?: () => number },
): { get: () => Promise<TierLabel[]> } {
  const now = opts.now ?? Date.now;
  let held: { until: number; labels: TierLabel[] } | null = null;
  let loading: Promise<TierLabel[]> | null = null;
  return {
    get() {
      if (held && now() < held.until) return Promise.resolve(held.labels);
      loading ??= load()
        .then(({ labels, complete }) => {
          held = { until: now() + (complete ? opts.ttlMs : opts.failedTtlMs), labels };
          return labels;
        })
        .finally(() => {
          loading = null;
        });
      return loading;
    },
  };
}

const labels = labelCache(loadTierLabels, { ttlMs: 10 * 60_000, failedTtlMs: 60_000 });

export const StripeService = {
  /** The Checkout URL for the website's donate button. */
  async createCheckout(baseUrl: string, choice: DonationChoice): Promise<string> {
    const session = await stripeClient().checkout.sessions.create(checkoutSessionParams(baseUrl, choice));
    if (!session.url) throw new Error("Stripe returned a checkout session with no URL");
    return session.url;
  },

  /** Verifies and parses a raw webhook payload. */
  constructEvent(rawBody: Buffer, signature: string) {
    return stripeClient().webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET!);
  },

  /**
   * Labels for the configured tiers, read from Stripe and kept for 10
   * minutes, so page views do not become Stripe API calls; a fallback label
   * when unreachable, kept for a minute.
   */
  tierLabels(): Promise<TierLabel[]> {
    return labels.get();
  },
};
