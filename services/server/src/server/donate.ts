import type { IncomingMessage, ServerResponse } from "node:http";
import { logger } from "../common/logger";
import { DB } from "./db/api";
import { type DonationChoice, monthlyTiersAvailable, oneTimeAvailable, StripeService, tierCount } from "./stripe";

/**
 * Origin-served donation pages: /donate (fallback offer), /donate/checkout,
 * /donate/thanks, /donate/cancelled and /supporters. The marketing Worker
 * serves the main /donate page by exact path; everything else falls through to
 * here.
 */

function baseUrl(req: IncomingMessage): string {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL;
  const host = req.headers.host || "localhost";
  const proto = (req.headers["x-forwarded-proto"] as string) || "https";
  return `${proto}://${host}`;
}

/** HTML-escapes donor-supplied text. */
function esc(s: string): string {
  return s.replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string,
  );
}

function page(title: string, inner: string): string {
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · hqchat</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:linear-gradient(160deg,#5b6cff 0%,#8b5cf6 100%); min-height:100vh;
         display:flex; align-items:center; justify-content:center; padding:24px; }
  .card { background:#fff; color:#111; max-width:440px; width:100%; border-radius:20px;
          padding:32px; box-shadow:0 20px 60px rgba(0,0,0,.25); }
  h1 { font-size:1.5rem; margin:0 0 8px; }
  p { color:#555; line-height:1.5; }
  ol, ul { color:#555; line-height:1.6; padding-left:20px; }
  button { width:100%; padding:14px; font:inherit; font-weight:600; color:#fff;
           background:#5b6cff; border:0; border-radius:12px; cursor:pointer; margin-top:12px; }
  .logo { width:64px; height:64px; border-radius:18px; margin:0 auto 16px;
          background:linear-gradient(135deg,#5b6cff,#8b5cf6); display:flex; align-items:center;
          justify-content:center; font-size:30px; }
  .names { list-style:none; padding:0; }
  .names li { padding:8px 0; border-bottom:1px solid #eee; color:#111; }
  .muted { color:#777; font-size:.9rem; }
</style></head>
<body><div class="card"><div class="logo">✦</div>${inner}</div></body></html>`;
}

/**
 * Stripe Checkout's origin. It must be in the CSP `form-action`, which also
 * governs redirects: without it the browser silently drops the 302 to Stripe.
 */
export const CHECKOUT_ORIGIN = "https://checkout.stripe.com";

/** No scripts, inline styles only, forms to self and Stripe Checkout. */
export const CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
  `form-action 'self' ${CHECKOUT_ORIGIN}`,
  "base-uri 'none'",
].join("; ");

/** 503 page for a server with no prices configured. */
function unconfigured(res: ServerResponse) {
  return send(
    res,
    503,
    page(
      "Donations unavailable",
      `<h1>Donations are off right now</h1>
    <p>This server has no payment configured, so none of the buttons can take
       anything. That is our end, not yours — nothing was charged and there is
       nothing to retry.</p>
    <p class="muted">The app is free and entirely unaffected; a donation never
       changed anything about it.</p>`,
    ),
  );
}

function send(res: ServerResponse, status: number, body: string) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
  });
  res.end(body);
}

/** A urlencoded form body of at most 4 KiB. */
async function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > 4096) throw new Error("form body too large");
    chunks.push(c as Buffer);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

/** Pages with no inputs. */
const STATIC_PAGES: Record<string, [string, string]> = {
  "/donate/thanks": [
    "Thank you",
    `<h1>Thank you 🙏</h1>
    <p>That goes straight to the bill — servers, a database and a developer
       account.</p>
    <p>There is nothing to do next. You already had the whole app, and you
       still do; a donation does not change your account in any way.</p>
    <p class="muted">Stripe has emailed you a receipt. If you asked to be
       named, you will appear on the <a href="/supporters">supporters</a>
       page.</p>`,
  ],
  "/donate/cancelled": [
    "Cancelled",
    `<h1>Nothing was charged</h1>
    <p>No payment was taken. The app is free either way — come back whenever,
       or don't.</p>`,
  ],
};

async function supportersPage(res: ServerResponse): Promise<void> {
  const supporters = await DB.listSupporters();
  const list =
    supporters.length === 0
      ? `<p class="muted">Nobody yet. This page is written by the people who
         choose to be on it — donating does not put you here unless you type a
         name at checkout.</p>`
      : `<ul class="names">${supporters.map((s) => `<li>${esc(s.name)}</li>`).join("")}</ul>`;
  send(
    res,
    200,
    page(
      "Supporters",
      `<h1>Supporters</h1>
    <p>People who funded the servers, and asked to be named.</p>
    ${list}
    <p class="muted">No account, email or payment is linked to any name here —
       the name is all this server keeps.</p>`,
    ),
  );
}

/** The fallback offer: one button per configured tier, plus a one-time gift. */
async function offerPage(res: ServerResponse): Promise<void> {
  if (!monthlyTiersAvailable() && !oneTimeAvailable()) return unconfigured(res);
  const tiers = monthlyTiersAvailable()
    ? (await StripeService.tierLabels())
        .map((t, i) => `<button type="submit" name="choice" value="tier${i}">${esc(t.label)}</button>`)
        .join("")
    : "";
  send(
    res,
    200,
    page(
      "Donate",
      `<h1>Support hqchat</h1>
    <p>The app is free and always will be. This pays for the servers it runs
       on — it buys you nothing, and everyone has every feature either way.</p>
    <form method="POST" action="/donate/checkout">
      ${tiers}
      ${oneTimeAvailable() ? `<button type="submit" name="choice" value="once">give once</button>` : ""}
    </form>
    <p class="muted">Not a registered charity and not tax-deductible. This is
       one person's project and one person's server bill.</p>`,
    ),
  );
}

/** `once`, or `tierN` indexing the configured monthly tiers; null when not offered here. */
function parseChoice(choice: string): DonationChoice | null {
  const tier = /^tier(\d{1,2})$/.exec(choice);
  const donation: DonationChoice = tier ? { kind: "monthly", index: Number(tier[1]) } : { kind: "once" };
  const known = donation.kind === "once" ? oneTimeAvailable() : donation.index < tierCount();
  return known ? donation : null;
}

/** Redirects to Stripe Checkout for the posted choice. */
async function startCheckout(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const choice = ((await readForm(req)).get("choice") || "once").trim();
  const donation = parseChoice(choice);
  if (!donation) {
    // Printable and bounded before it reaches the log.
    const shown = choice.replace(/[^\x20-\x7e]/g, "").slice(0, 32);
    // Nothing priced is the operator's fault (the Worker shows every button); anything else is the caller's.
    if (!monthlyTiersAvailable() && !oneTimeAvailable()) {
      logger.warn(
        `[donate] refused "${shown}" — nothing is priced on this server. ` +
          `Set STRIPE_DONATION_PRICE_IDS / STRIPE_DONATION_ONCE_PRICE_ID.`,
      );
      return unconfigured(res);
    }
    logger.debug(`[donate] unknown choice "${shown}"`);
    return send(
      res,
      400,
      page(
        "Unknown option",
        `<h1>That option is not available</h1>
    <p>Go back and pick one of the amounts shown.</p>`,
      ),
    );
  }

  const checkoutUrl = await StripeService.createCheckout(baseUrl(req), donation);
  if (!checkoutUrl.startsWith(`${CHECKOUT_ORIGIN}/`)) {
    logger.error(
      `[donate] checkout URL origin is not ${CHECKOUT_ORIGIN} — the CSP form-action ` +
        `will block this redirect and the button will do nothing. Got: ${new URL(checkoutUrl).origin}`,
    );
  }
  res.writeHead(302, { Location: checkoutUrl });
  res.end();
}

/** Handles /donate* and /supporters: GET renders a page, POST starts checkout. */
export async function handleDonate(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const path = new URL(req.url || "/", "http://localhost").pathname;
  try {
    const fixed = STATIC_PAGES[path];
    if (fixed) return send(res, 200, page(...fixed));
    if (path === "/supporters") return await supportersPage(res);
    if (req.method !== "POST") return await offerPage(res);
    return await startCheckout(req, res);
  } catch (e) {
    logger.error("[donate] error:", (e as Error).message);
    if (res.headersSent) {
      res.end();
      return;
    }
    send(
      res,
      500,
      page(
        "Error",
        `<h1>Something went wrong</h1>
      <p>Please try again in a moment.</p>`,
      ),
    );
  }
}
