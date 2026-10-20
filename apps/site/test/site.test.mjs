/**
 * The previous marketing Worker had no tests at all — CI only ran
 * `terraform validate` over the edge config, so nothing watched the HTML or the
 * headers. These are the assertions that would have caught the bugs this site
 * has actually had.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import worker from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");

// The site's own host. Every assertion below asks for a page AS hqchat.app,
// because asking as anything else now gets a 301 — which is the point, and is
// covered by its own tests at the bottom of this file.
const ORIGIN = "https://hqchat.app";
// Any host that is not the canonical one: the rule is "anything else
// redirects".
const OTHER_ORIGIN = "https://hqchat.example";
const get = (path) => worker.fetch(new Request(`${ORIGIN}${path}`));
const ROUTES = ["/", "/crypto", "/donate", "/privacy", "/terms", "/eula", "/support"];
// Routed to the Worker, and answered by it, but NOT HTML — so every assertion
// below that reads a document has to skip them, and the edge cross-check has to
// not. Keeping them in a second list is what makes both of those automatic.
const FILES = ["/robots.txt", "/sitemap.xml"];
// The listing the site now links at. Written out once here, on purpose: these
// tests are the only thing standing between a typo'd store id and a launch
// announcement that links to somebody else's app.
const APP_STORE_URL = "https://apps.apple.com/app/hqchat/id6786412967";

test("every routed path answers 200 with HTML", async () => {
  for (const path of ROUTES) {
    const res = await get(path);
    assert.equal(res.status, 200, `${path} should be 200`);
    assert.match(res.headers.get("content-type"), /text\/html/);
    const body = await res.text();
    assert.match(body, /^<!doctype html>/, `${path} should be a full document`);
    assert.match(body, /<title>[^<]+· hqchat<\/title>/, `${path} needs a title`);
  }
});

test("anything else is a 404, not a 200", async () => {
  for (const path of ["/pricing", "/subscribe"]) {
    const res = await get(path);
    assert.equal(res.status, 404, `${path} must not be a page on this site`);
  }
});

/**
 * The one that matters. `form-action` is enforced across the 302 from
 * /donate/checkout out to Stripe, and it is checked against THIS page's policy.
 * If the Stripe origin is missing the browser drops the redirect silently: a
 * clean 302 in the log and a button that does nothing. It has happened before —
 * see the postmortem in services/server/src/server/donate.ts.
 */
test("the CSP lets the donate form redirect out to Stripe", async () => {
  for (const path of ROUTES) {
    const csp = (await get(path)).headers.get("content-security-policy");
    assert.ok(csp, `${path} must set a CSP`);
    assert.match(csp, /form-action [^;]*'self'/, `${path}: form-action must be stated`);
    assert.match(
      csp,
      /form-action [^;]*https:\/\/checkout\.stripe\.com/,
      `${path}: form-action must name the Stripe origin or the button dies silently`,
    );
  }
});

test("widening form-action did not loosen anything else", async () => {
  const csp = (await get("/")).headers.get("content-security-policy");
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.doesNotMatch(csp, /script-src/, "no script-src: this site runs no JavaScript");
});

/**
 * Drift guard. The Worker cannot import from the server package, so the Stripe
 * origin is written down twice. If Checkout ever moves to a custom domain, this
 * fails loudly instead of the button going quiet.
 */
test("the Stripe origin matches the server's CHECKOUT_ORIGIN", async () => {
  const src = readFileSync(join(REPO, "services/server/src/server/donate.ts"), "utf8");
  const m = src.match(/CHECKOUT_ORIGIN\s*=\s*"([^"]+)"/);
  assert.ok(m, "could not find CHECKOUT_ORIGIN in donate.ts");
  const csp = (await get("/")).headers.get("content-security-policy");
  assert.ok(csp.includes(m[1]), `server uses ${m[1]}; this site's CSP does not name it`);
});

test("the donate form posts to the origin and asks for nothing", async () => {
  for (const path of ["/", "/crypto", "/donate"]) {
    const body = await (await get(path)).text();
    assert.match(
      body,
      /<form method="POST" action="\/donate\/checkout">/,
      `${path}: the form must POST same-origin to /donate/checkout`,
    );
    assert.doesNotMatch(
      body,
      /<input/i,
      `${path}: no inputs — Stripe collects everything at checkout, including the
       optional supporters-page name`,
    );
  }
});

/**
 * The page asks for money, so it has to be unambiguous about what money buys.
 * These are the three sentences a donation page can most easily be sued or
 * shamed over, and the three this project has committed to saying.
 */
/**
 * Drift guard, and an honest statement of its own limit.
 *
 * The buttons post an INDEX (`tier0`, `tier1`, …) into the operator's
 * `STRIPE_DONATION_PRICE_IDS`, never a price id — so no Stripe id lives in this
 * site at all, and the check that matters is that the two lists are the same
 * length and in the same order.
 *
 * What CANNOT be checked here: whether a LABEL matches what Stripe actually
 * charges. This is a static Worker with no way to reach Stripe at render time,
 * so an amount changed in Stripe and not here shows one number and charges
 * another. That check does not exist and cannot be written on this side.
 */
test("there is a button for every configured tier, and no extras", async () => {
  const env = JSON.parse(readFileSync(join(REPO, "infra/environments/production.json"), "utf8"));
  const tiers = env.donations.monthlyPriceIds;
  assert.ok(tiers.length > 0, "the production environment must configure its prices");

  const body = await (await get("/donate")).text();
  const posted = [...body.matchAll(/name="choice" value="([^"]+)"/g)].map((m) => m[1]);
  const indices = posted.filter((v) => v.startsWith("tier")).map((v) => Number(v.slice(4)));

  // Contiguous from 0, one per configured price. A site with fewer buttons than
  // prices quietly stops offering a tier; one with more sends `tierN` for an N
  // the server cannot resolve, and the donor meets "that option is not
  // available".
  assert.deepEqual(
    indices,
    tiers.map((_, i) => i),
    "tier buttons must index the configured monthly prices exactly, in order",
  );
  assert.ok(posted.includes("once"), "the one-time button must be offered");
});

test("no Stripe price id appears anywhere on the site", async () => {
  // The site posts indices, so it never needs one. If an id shows up here it
  // means this deployment's Stripe account has been baked into the marketing
  // source, and a fork would ship buttons pointed at someone else's prices.
  for (const path of ROUTES) {
    const body = await (await get(path)).text();
    assert.doesNotMatch(body, /price_[A-Za-z0-9]{6,}/, `${path} must carry no price id`);
  }
});

test("the tier buttons render low to high", async () => {
  // The order is the order of STRIPE_DONATION_PRICE_IDS — and since the buttons
  // now post positions rather than ids, a reordered label list would charge the
  // wrong amount rather than merely displaying one. This is the guard that
  // makes the index safe.
  const body = await (await get("/donate")).text();
  const amounts = [...body.matchAll(/value="tier\d+">€(\d+) \/ month</g)].map((m) => Number(m[1]));
  assert.ok(amounts.length >= 2, "expected the monthly tiers to render");
  assert.deepEqual(
    amounts,
    [...amounts].sort((a, b) => a - b),
    "tiers must render low to high, or the index points at the wrong price",
  );
});

test("the donate page states that a donation buys nothing", async () => {
  const body = await (await get("/donate")).text();
  assert.match(body, /buys <strong>nothing<\/strong>/i, "the ask must say outright that a donation unlocks no feature");
  assert.match(body, /not tax-deductible/i, "it must not let anyone infer a charitable deduction");
  assert.match(body, /no foundation/i, "no legal entity exists; the page must not imply one");
});

test("no page offers to sell anything", async () => {
  // The whole product is free, and the App Store listing is written from the
  // same claims. Matched as phrases, not words: a bare word list flags "a
  // donation unlocks nothing". The negative lookbehind keeps "there is no
  // subscription, no paid tier and no in-app purchase" from matching.
  const notNegated = "(?<!no )(?<!not )(?<!never )(?<!nor )";
  const selling = [
    "unlocks? (?:contacts|the app|features|conversations)",
    "subscribe to\\b",
    "paid (?:tier|plan|version|account)\\b",
    "premium\\b",
    "upgrade (?:to|your|for)\\b",
    "free (?:tier|plan)\\b",
  ].map((p) => new RegExp(`${notNegated}\\b${p}`, "i"));
  for (const path of ROUTES) {
    const body = await (await get(path)).text();
    for (const phrase of selling) {
      assert.doesNotMatch(body, phrase, `${path}: ${phrase} reads as selling something`);
    }
  }
});

test("nothing on the page needs a network fetch the CSP would block", async () => {
  for (const path of ROUTES) {
    const body = await (await get(path)).text();
    // The site runs no JavaScript, and this is the assertion that keeps it that
    // way. It is NOT a ban on the <script> element: a
    // `type="application/ld+json"` block is a data block — the parser never
    // hands it to an engine, CSP does not gate it, and it is the only
    // machine-readable way to state that this page is about a free iOS app.
    // Every OTHER script tag, typed or not, is the thing being forbidden.
    for (const tag of body.match(/<script\b[^>]*>/gi) ?? []) {
      assert.equal(
        tag,
        '<script type="application/ld+json">',
        `${path}: the only permitted script element is the ld+json data block`,
      );
    }
    assert.doesNotMatch(body, /<link[^>]+stylesheet/i, `${path}: stylesheets must be inlined`);
    assert.doesNotMatch(body, /src="https?:/i, `${path}: no remote assets`);
    // w3.org is exempt, and only w3.org: the inline SVG favicon carries the SVG
    // namespace NAME, which is spelled http:// by the spec and is never fetched
    // by anything. A plaintext http:// anywhere else is still a finding.
    assert.doesNotMatch(body.replaceAll("http://www.w3.org/", ""), /http:\/\//, `${path}: no plaintext http URLs`);
  }
});

/** Claims the repo's own docs contradict. Cheap to assert, expensive to ship. */
test("the copy does not re-introduce claims that are not true", async () => {
  for (const path of ROUTES) {
    const body = await (await get(path)).text();
    assert.doesNotMatch(
      body,
      /zero.knowledge/i,
      `${path}: the server knows the graph, usernames and timing — do not say zero-knowledge`,
    );
    // The old site's landing copy read "end-to-end encrypted messages & calls".
    // Calls, photos and voice notes were cut from v0; the words may appear only
    // where the page says they are missing, never in a claim.
    assert.doesNotMatch(
      body,
      /encrypted[^<.]{0,60}\bcalls\b/i,
      `${path}: calls are cut from v0 — do not advertise them`,
    );
    assert.doesNotMatch(body, /photos,? and (voice|video)/i, `${path}: photos and voice notes are cut from v0`);
  }
  const home = await (await get("/")).text();
  assert.match(home, /no calls, photos or voice notes/i, "the v0 scope disclaimer must stay on the front page");
  assert.match(home, /not a hybrid/i, "the pure-HQC caveat must stay on the front page");
});

/** The exact paths Terraform routes to the Worker (infra/terraform/cloudflare.tf). */
function workerPaths() {
  const tf = readFileSync(join(REPO, "infra", "terraform", "cloudflare.tf"), "utf8");
  const list = tf.slice(tf.indexOf("worker_paths"), tf.indexOf("]", tf.indexOf("worker_paths")));
  return [...list.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
}

/**
 * The edge decides which paths reach this Worker, and it takes EXACT paths — a
 * page that exists here but is missing from `worker_paths` does not 404 at the
 * edge, it falls through to the origin, which answers a REST 404. So the failure
 * looks like a broken link rather than a missing route, and nothing in this repo
 * would have noticed.
 *
 * That matters most for /eula, which is the URL App Store Connect is given as
 * the custom EULA: the first person to find it broken would be an app reviewer.
 */
test("every routed page is also routed AT THE EDGE", async () => {
  const routed = workerPaths();
  assert.ok(routed.length > 0, "worker_paths did not parse");
  for (const path of [...ROUTES, ...FILES]) {
    assert.ok(
      routed.includes(path),
      `${path} answers 200 here but is not in worker_paths — it would reach the API instead`,
    );
  }
  // And the other direction, which is the cheaper mistake: a path routed to the
  // Worker that the Worker does not serve is a 404 the edge could have avoided.
  for (const path of routed) {
    assert.ok([...ROUTES, ...FILES].includes(path), `worker_paths routes ${path}, which this Worker 404s`);
  }
});

test("the eula is the Guideline 1.2 page, and says the things that make it one", async () => {
  // Apple asks a user-generated-content app for four mechanisms TOGETHER. Three
  // of them are in the app; this page is the fourth and is where a reviewer
  // checks for the other three. Each assertion below is a rejection if it stops
  // being true.
  const eula = await (await get("/eula")).text();
  assert.match(eula, /zero tolerance/i, "1.2 asks for a stated zero-tolerance policy");
  assert.match(eula, /report/i, "…a mechanism to report content");
  assert.match(eula, /block/i, "…a mechanism to block abusive users");
  assert.match(eula, /24 hours/i, "…and acting on reports within 24 hours");

  // The two sentences that keep the feature honest. Both are also said in the
  // app, on the screen where a report is sent; if either disappears from here,
  // the page is claiming a verification that does not exist.
  assert.match(eula, /not verifiable/i, "the page must say a reported excerpt cannot be verified");
  assert.match(
    eula,
    /uploads that message's text|uploads that message&#39;s text/i,
    "the page must say that reporting uploads the message text to the server",
  );

  // It has to be reachable from the app's own chrome, and linked from the pages
  // a reviewer lands on first.
  for (const from of ["/", "/terms", "/privacy", "/support"]) {
    assert.match(await (await get(from)).text(), /href="\/eula"/, `${from} does not link to the eula`);
  }
});

test("the privacy page no longer makes a claim the report feature broke", async () => {
  // It said "No message content — we cannot decrypt it", full stop, and that
  // sentence stopped being unconditionally true the moment a report could carry
  // an excerpt. The fix is not to delete the sentence — it is still true of
  // everything except a message the user chose to hand in — but to carry the
  // exception beside it, in all three places the page makes the claim.
  const privacy = await (await get("/privacy")).text();
  assert.match(privacy, /report/i, "the privacy page does not mention reporting at all");
  assert.match(privacy, /90 days/i, "…nor how long a report is kept");
  assert.match(privacy, /href="\/eula"/, "…nor link to the agreement that sets the rule");

  // The deletion promise. A report ABOUT a deleted account survives, and saying
  // so is the difference between an exception and a broken promise.
  const deletion = privacy.slice(privacy.indexOf("deleting your account"));
  assert.match(
    deletion.slice(0, 2000),
    /survives your account deletion/i,
    "the deletion section must say that reports about you outlive your account",
  );

  // And the public "what the server holds" table, which is the version most
  // people actually read. Asserted on the ROW, not on the page: "exception"
  // appears in plenty of prose, and a page-wide match would keep passing with
  // the row restored to its absolute claim.
  for (const path of ["/", "/crypto"]) {
    const page = await (await get(path)).text();
    const i = page.indexOf("✗ your messages");
    if (i < 0) continue; // the table is not on this page
    const row = page.slice(i, page.indexOf("</tr>", i));
    assert.match(
      row,
      /report/i,
      `${path}'s "what the server holds" table still says messages never leave the device, ` +
        "with no mention of the one path that moves one",
    );
  }
});

test("legal pages carry the corrections that brought them back in line", async () => {
  const privacy = await (await get("/privacy")).text();
  assert.doesNotMatch(
    privacy,
    /7 days|seven days/i,
    "the 7-day server-side queue no longer exists; it is the broker session now",
  );
  assert.doesNotMatch(privacy, /in-app purchase/i, "StoreKit was removed; nothing is sold through Apple");
  const terms = await (await get("/terms")).text();
  assert.match(terms, /Stripe/, "terms must name who actually bills");
});

/**
 * The crypto pages described v1 for four days after v1 stopped existing.
 *
 * v1 was a symmetric mutual encapsulation to identity keys, with the two shared
 * secrets sorted so neither side was the initiator, and a static channel key
 * until the first re-key at 100 messages. v2 is PQXDH-shaped: the initiator
 * encapsulates to an identity key AND two prekeys, and every message is
 * ratcheted from the first.
 *
 * Describing the weaker, superseded protocol is not a harmless stale doc on a
 * page whose entire argument is that you can go and check the claims.
 */
test("the crypto copy describes v2, not the protocol it replaced", async () => {
  const body = await (await get("/crypto")).text();

  assert.match(body, /prekey/i, "v2 is prekey-based — say so");
  assert.match(
    body,
    /sha256\(senderPk\)|CHECK sha256/i,
    "the key–name commitment is the property that makes TOFU narrow; keep it visible",
  );

  assert.doesNotMatch(
    body,
    /sort\(mySs, peerSs\)/,
    "sorted shared secrets were v1's way of removing an initiator; v2 is asymmetric",
  );
  assert.doesNotMatch(
    body,
    /every 100 messages/i,
    "the 100-message re-key was v1; v2 steps at 32 messages or 15 minutes",
  );
});

/**
 * Drift guard for the two numbers that ARE the post-compromise-security window.
 *
 * They moved once already — the interval went 60 s → 15 min in #130, because at
 * 60 s every reply in an ordinary conversation carried a full ~29 kB step. The
 * page states both numbers as a security property, so a change in the code that
 * does not reach the copy leaves the site advertising a window that is not the
 * one shipping.
 */
test("the ratchet numbers on the page are the ones in the code", async () => {
  // The Rust core is the implementation every client and the server run.
  const src = readFileSync(join(REPO, "core/hqchat-protocol/src/ratchet.rs"), "utf8");
  const num = (name) => Number(src.match(new RegExp(`${name}: \\w+\\s*=\\s*([0-9_]+)`))?.[1].replace(/_/g, ""));
  const maxMessages = num("RATCHET_MAX_MESSAGES_PER_CHAIN");
  const intervalMin = num("RATCHET_MIN_STEP_INTERVAL_MS") / 60_000;
  assert.ok(maxMessages > 0 && intervalMin > 0, "could not read the RATCHET_* constants");

  for (const path of ["/", "/crypto"]) {
    const body = await (await get(path)).text();
    assert.match(
      body,
      new RegExp(`<b>${maxMessages} messages</b>|<b>${maxMessages}</b> messages`),
      `${path}: the page must name ${maxMessages} messages`,
    );
    assert.match(
      body,
      new RegExp(`<b>${intervalMin} minutes</b>`),
      `${path}: the page must name ${intervalMin} minutes, not a stale interval`,
    );
    assert.doesNotMatch(body, /lived <b>60 seconds<\/b>/, `${path}: the 60-second step interval is gone`);
  }
});

/**
 * An `init` alone proves nothing about who sent it: every value in one is
 * public. First contact is a challenge–response round trip, and the page must
 * not promise one flight.
 */
test("the page does not still promise a one-flight first contact", async () => {
  const src = readFileSync(join(REPO, "core/hqchat-protocol/src/handshake.rs"), "utf8");
  const info = src.match(/INFO_PREFIX: &\[u8\] = b"([^"]+)"/)?.[1];
  assert.ok(info, "could not read the handshake info prefix");

  const crypto = await (await get("/crypto")).text();
  assert.ok(crypto.includes(info), `/crypto must quote the handshake info string (${info}) it binds the proof with`);
  for (const path of ["/", "/crypto"]) {
    const body = await (await get(path)).text();
    assert.doesNotMatch(
      body,
      /first contact needs no round trip/i,
      `${path}: an init is held until the sender proves it holds the key it claims`,
    );
  }
});

test("the crypto page says v2 is gone, not merely superseded", async () => {
  const body = await (await get("/crypto")).text();

  // ⚠️ A bare /deleted/i match here is VACUOUS: the frame diagram on the same
  // page carries the word too, so the prose could say "superseded" and this
  // would still pass. Verified by injection. The assertion is scoped to the
  // PROSE, which is the half a reader takes a claim from.
  const prose = body.slice(body.indexOf("There used to be two formats"));
  assert.ok(
    prose.length > 0 && prose.length < body.length,
    "the wire-format section is not where this test expects it",
  );
  assert.match(
    prose.slice(0, 600),
    /deleted — nothing reads it/i,
    "/crypto must say v2 is deleted, not merely superseded",
  );
  assert.match(
    body,
    /refused like any other\s*\n?\s*non-frame|refused like any other non-frame/i,
    "…and that a v2 frame is now refused rather than parsed",
  );

  // The frame layout is the thing a reader checks the claims against, so it has
  // to still be on the page.
  assert.match(body, /HQCE/, "/crypto must still show the frame's magic");
  assert.match(body, /the header ends here/i, "…and where the AAD stops");
});

/** The identifier stopped being a public key in #108. */
test("the copy names client ids where the server stores ids", async () => {
  // SERVER_TABLE is shared by both pages, so this claim has to be right twice.
  for (const path of ["/", "/crypto"]) {
    const body = await (await get(path)).text();
    assert.doesNotMatch(
      body,
      /rows naming both public keys/i,
      `${path}: friendships store client ids (sha256 of the key), not the keys`,
    );
  }
  // How topics come to be is spelled out on /crypto only: the server mints
  // them at random (001_baseline.sql), and the broker's ACL is a static file.
  const crypto = await (await get("/crypto")).text();
  assert.match(crypto, /244\s+random bits/i, "conversation topics are random ids, with their real entropy");
  assert.doesNotMatch(crypto, /sorted client ids/i, "topics are not derived from the two ids");
  assert.doesNotMatch(crypto, /ACL in Postgres/i, "the broker's ACL is a static file, not a database lookup");
});

/** The broker keeps an offline session two hours and 1000 messages (EMQX's defaults). */
test("the copy states how long the broker holds undelivered messages", async () => {
  for (const path of ["/", "/privacy"]) {
    const body = await (await get(path)).text();
    assert.doesNotMatch(
      body,
      /until (your device|you) reconnects?/i,
      `${path}: an offline session does not wait forever`,
    );
    assert.match(body, /1000\s+messages/i, `${path}: names the queue limit`);
    assert.match(body, /two\s+hours/i, `${path}: names the session expiry`);
  }
});

/** Observability.swift sends crash and hang reports only. */
test("the privacy policy describes what Sentry receives", async () => {
  const body = await (await get("/privacy")).text();
  assert.doesNotMatch(body, /performance (diagnostics|signals)/i, "the app sends no performance data");
  assert.match(body, /no user or installation identifier/i, "reports carry no user or installation id");
  assert.match(body, /no screenshots\s+or screen recordings/i, "and no screen images");
});

/* ────────────────────────────────────────────────────────────────────────────
 * Discoverability.
 *
 * The site shipped for months with ONE description shared by every page, no
 * canonical, no robots.txt and no sitemap — which is not a small oversight on a
 * page whose job is to be found by someone who has heard of post-quantum
 * messaging and not of this. These are the assertions that keep it fixed.
 * ──────────────────────────────────────────────────────────────────────────── */

/** `<meta content="...">` — the pages are HTML strings, so read them as such. */
const meta = (body, key) => {
  const re = new RegExp(`<meta (?:name|property)="${key}" content="([^"]*)"`, "i");
  return body.match(re)?.[1] ?? null;
};

test("every page declares its own canonical URL, and it is its own", async () => {
  // A canonical pointing at the wrong page is worse than none: it asks a search
  // engine to drop THIS page and keep the other one.
  for (const path of ROUTES) {
    const body = await (await get(path)).text();
    const canonical = body.match(/<link rel="canonical" href="([^"]+)"/)?.[1];
    assert.equal(canonical, ORIGIN + path, `${path}: wrong or missing canonical`);
    assert.equal(meta(body, "og:url"), ORIGIN + path, `${path}: og:url must agree with it`);
  }
});

test("the 404 is noindex and claims no address of its own", async () => {
  const res = await get("/nope");
  assert.equal(res.status, 404);
  const body = await res.text();
  assert.match(meta(body, "robots"), /noindex/, "an error page must not be indexed");
  assert.doesNotMatch(body, /rel="canonical"/, "…and has no canonical to declare");
  assert.doesNotMatch(body, /og:url/, "…nor an og:url");
});

test("no two pages share a meta description", async () => {
  // This is the specific bug being guarded. One description across seven pages
  // is how a site tells a crawler its pages are duplicates of one another.
  const seen = new Map();
  for (const path of ROUTES) {
    const body = await (await get(path)).text();
    const desc = meta(body, "description");
    assert.ok(desc, `${path}: no meta description`);
    assert.ok(desc.length >= 60, `${path}: description is too thin to be useful`);
    // ~155 chars is where a result snippet is cut. 170 is the slack this allows
    // before the tail of a sentence is being written for nobody.
    assert.ok(desc.length <= 170, `${path}: ${desc.length} chars — a description this long is truncated in the result`);
    assert.ok(!seen.has(desc), `${path} reuses the description from ${seen.get(desc)}`);
    seen.set(desc, path);

    // Whatever else it says, it must be safe in an attribute.
    assert.doesNotMatch(desc, /["<>]/, `${path}: description must be attribute-safe`);
    assert.ok(body.includes(`<meta name="robots" content="index, follow`), `${path} must be indexable`);
  }
});

test("the social card mirrors the page, rather than inventing a second one", async () => {
  for (const path of ROUTES) {
    const body = await (await get(path)).text();
    const title = body.match(/<title>([^<]+)<\/title>/)[1];
    const desc = meta(body, "description");
    assert.equal(meta(body, "og:title"), title, `${path}: og:title drifted from <title>`);
    assert.equal(meta(body, "og:description"), desc, `${path}: og:description drifted`);
    assert.equal(meta(body, "twitter:title"), title, `${path}: twitter:title drifted`);
    assert.equal(meta(body, "twitter:description"), desc, `${path}: twitter:description drifted`);
    assert.equal(meta(body, "og:site_name"), "hqchat");
    assert.equal(meta(body, "twitter:card"), "summary");
  }
});

test("every page has exactly one h1", async () => {
  // The front page had none at all: the wordmark was a <div>. That is an
  // accessibility gap before it is anything else — a screen reader gets no
  // document title from the body — and the fix is the same either way.
  for (const path of ROUTES) {
    const body = await (await get(path)).text();
    const h1s = body.match(/<h1[\s>]/g) ?? [];
    assert.equal(h1s.length, 1, `${path} has ${h1s.length} <h1> elements, expected exactly 1`);
  }
});

/* ── robots.txt and sitemap.xml ──────────────────────────────────────────── */

test("robots.txt is plain text, and points at the sitemap", async () => {
  const res = await get("/robots.txt");
  assert.equal(res.status, 200);
  // The content type is the assertion that matters. Served as text/html with
  // `nosniff`, a crawler parses it as markup and ignores every rule in it.
  assert.match(res.headers.get("content-type"), /^text\/plain/);
  const body = await res.text();
  assert.doesNotMatch(body, /<html|<!doctype/i, "robots.txt must not be the 404 page");
  assert.match(body, /^User-agent: \*$/m);
  assert.match(body, /^Allow: \/$/m);
  // Absolute, per the standard — a relative Sitemap: line is ignored outright.
  assert.match(body, new RegExp(`^Sitemap: ${ORIGIN}/sitemap\\.xml$`, "m"));
  // The disallow list covers the ORIGIN's paths, not just this Worker's: they
  // share a host, and robots.txt is per host.
  assert.match(body, /^Disallow: \/donate\/checkout$/m, "crawling checkout mints Stripe sessions");
  for (const page of ROUTES) {
    assert.doesNotMatch(
      body,
      new RegExp(`^Disallow: ${page}$`, "m"),
      `robots.txt blocks ${page}, which is a page this site wants indexed`,
    );
  }
});

test("the sitemap lists exactly the pages this Worker serves", async () => {
  const res = await get("/sitemap.xml");
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type"), /^application\/xml/);
  const body = await res.text();
  assert.match(body, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
  assert.match(body, /xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9"/);

  const locs = [...body.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  assert.deepEqual(
    locs,
    ROUTES.map((p) => ORIGIN + p),
    "the sitemap and the router must list the same pages, in the same order",
  );

  // /supporters is a real public page, and it is NOT this Worker's to list: it
  // needs the database and is served from the origin.
  assert.doesNotMatch(body, /supporters/, "the sitemap must not claim origin-served pages");
  // Absent on purpose — see the comment on SITEMAP_XML. A constant lastmod
  // stamped across every page is a freshness claim that is false for six of
  // them, and a sitemap caught lying about dates is discounted wholesale.
  assert.doesNotMatch(
    body,
    /lastmod|changefreq|priority/,
    "no lastmod: there is no per-page modification date to put in it",
  );
});

test("the sitemap and robots.txt are not swallowed by the HTML router", async () => {
  // Served as themselves, not as the 404 page with a 200.
  for (const path of FILES) {
    const body = await (await get(path)).text();
    assert.doesNotMatch(body, /<!doctype html>/i, `${path} is answering with the site`);
  }
});

/* ── the App Store listing ───────────────────────────────────────────────── */

test("the store link is the same listing everywhere it appears", async () => {
  // A typo in the track id links a launch announcement at a stranger's app, and
  // nothing about the page would look wrong.
  const home = await (await get("/")).text();
  const links = [...home.matchAll(/href="(https:\/\/apps\.apple\.com[^"]*)"/g)].map((m) => m[1]);
  assert.ok(links.length > 0, "the front page must link to the App Store");
  for (const href of links) assert.equal(href, APP_STORE_URL);

  // The Smart App Banner takes the numeric id on its own, so it is written down
  // a second way and can drift from the URL without either looking wrong.
  const id = APP_STORE_URL.match(/id(\d+)$/)[1];
  for (const path of ROUTES) {
    const body = await (await get(path)).text();
    assert.equal(
      meta(body, "apple-itunes-app"),
      `app-id=${id}`,
      `${path}: the Smart App Banner id must be the id in the link`,
    );
  }
});

test("no page still says the app is unreleased", async () => {
  // These sentences were true and are not any more. The site's whole argument is
  // that you can check its claims, so a stale one is expensive here.
  for (const path of ROUTES) {
    const body = await (await get(path)).text();
    assert.doesNotMatch(body, /not (?:on|yet on) the App Store/i, `${path}: the app is on the App Store`);
    assert.doesNotMatch(body, /nothing to install/i, `${path}: there is something to install`);
    assert.doesNotMatch(body, /not shipped yet/i, `${path}: it shipped`);
  }
});

test("the legal pages name the listing a reviewer would actually find", async () => {
  // They said "listed on the App Store as HQChat" — the working title. The
  // record is called hqChat, and a licence agreement naming a different app is
  // the kind of detail an App Review rejection is written about.
  for (const path of ["/privacy", "/terms", "/eula"]) {
    const body = await (await get(path)).text();
    assert.match(body, /listed on the App Store as hqChat/, `${path} must name the listing as it is published`);
    assert.doesNotMatch(body, /as HQChat/, `${path} names the pre-launch working title`);
  }
});

test("the structured data is on the home page, parses, and overstates nothing", async () => {
  const blocks = (body) =>
    [...body.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)].map((m) => JSON.parse(m[1]));

  for (const path of ROUTES.filter((p) => p !== "/")) {
    const body = await (await get(path)).text();
    assert.equal(
      blocks(body).length,
      0,
      `${path}: the app markup belongs on the home page alone, or it describes seven apps`,
    );
  }

  const home = await (await get("/")).text();
  const found = blocks(home);
  assert.equal(found.length, 1, "expected exactly one ld+json block on the home page");
  const graph = found[0]["@graph"];
  const app = graph.find((n) => n["@type"] === "MobileApplication");
  assert.ok(app, "the graph must describe the application");

  assert.equal(app.downloadUrl, APP_STORE_URL);
  assert.equal(app.installUrl, APP_STORE_URL);
  assert.equal(app.isAccessibleForFree, true);
  assert.equal(app.offers.price, "0", "the app is free; the offer must say 0");
  assert.equal(app.privacyPolicy, `${ORIGIN}/privacy`);

  // The two fields that must stay out. An invented rating is the most heavily
  // penalised thing this block could carry, and a version number here goes stale
  // on the next release with nothing to notice.
  assert.equal(app.aggregateRating, undefined, "the listing has no ratings — do not invent one");
  assert.equal(app.softwareVersion, undefined, "a version here drifts silently from the one on the store");

  // And it must not describe features the app does not have — the same claim the
  // prose is held to, in the half a human never reads.
  const features = app.featureList.join(" ");
  assert.doesNotMatch(features, /\bcalls?\b|voice note|group/i, "featureList advertises something cut from v0");
});

/* ────────────────────────────────────────────────────────────────────────────
 * The move to hqchat.app.
 *
 * hqchat.app is the one host, and anything else that reaches this Worker is
 * answered with a 301 rather than a copy of the page.
 *
 * The danger these cover is precise: the redirect fires before routing, so a
 * route list that ever grew an API path would answer an API call with "go
 * somewhere else" instead of serving it. Hence the worker_paths check below.
 * ──────────────────────────────────────────────────────────────────────────── */

test("the old host sends every page to hqchat.app, permanently", async () => {
  for (const path of [...ROUTES, ...FILES]) {
    const res = await worker.fetch(new Request(OTHER_ORIGIN + path));
    assert.equal(res.status, 301, `${path}: a 302 asks a search engine to keep the old url indexed`);
    assert.equal(res.headers.get("location"), ORIGIN + path, `${path}: must land on the same path, not the front page`);
    assert.equal(await res.text(), "", "a redirect carries no body");
  }
});

test("www.hqchat.app is not a second copy of the site", async () => {
  const res = await worker.fetch(new Request("https://www.hqchat.app/crypto"));
  assert.equal(res.status, 301);
  assert.equal(res.headers.get("location"), `${ORIGIN}/crypto`);
});

test("the redirect carries the query string across", async () => {
  // The site reads no parameters, but campaign tags arrive on links other
  // people wrote, and dropping them turns their attribution into direct traffic.
  const res = await worker.fetch(new Request(`${OTHER_ORIGIN}/?utm_source=launch&ref=hn`));
  assert.equal(res.headers.get("location"), `${ORIGIN}/?utm_source=launch&ref=hn`);
});

test("the redirect is cacheable, but not forever", async () => {
  // A 301 with no freshness information is cached by browsers until the profile
  // is wiped. That is how a redirect published by mistake follows somebody
  // around for months. Crawlers key off the status code, so bounding it costs
  // nothing in the thing the redirect exists for.
  const res = await worker.fetch(new Request(`${OTHER_ORIGIN}/`));
  const cc = res.headers.get("cache-control");
  assert.match(cc, /max-age=(\d+)/, "the 301 must state how long it may be cached");
  const age = Number(cc.match(/max-age=(\d+)/)[1]);
  assert.ok(age > 0 && age <= 86_400, `max-age=${age} is not a recoverable window`);
});

test("the redirect keeps the security headers", async () => {
  // A 301 is still a response from this site, and `nosniff` plus a frame-ancestors
  // of 'none' cost nothing on an empty body.
  const res = await worker.fetch(new Request(`${OTHER_ORIGIN}/`));
  assert.match(res.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
});

test("local and preview hosts are served, not redirected", async () => {
  // Without this carve-out `wrangler dev` answers every path with a redirect to
  // production, and iterating on the site locally consists of watching the
  // browser leave.
  for (const origin of ["http://localhost:8787", "https://hqchat-site.workers.dev"]) {
    const res = await worker.fetch(new Request(`${origin}/`));
    assert.equal(res.status, 200, `${origin} must serve the site, not redirect`);
  }
});

test("every address the site states is hqchat.app", async () => {
  // The canonical, og:url, the sitemap and robots.txt all name a host. If any of
  // them still named the old one, the 301 above would be pointing at a page that
  // disowns itself.
  for (const path of ROUTES) {
    const body = await (await get(path)).text();
    assert.doesNotMatch(body, /hqchat\.martinrougeron\.me/, `${path} still names the old host in its own markup`);
  }
  const robots = await (await get("/robots.txt")).text();
  assert.match(robots, new RegExp(`^Sitemap: ${ORIGIN}/sitemap\\.xml$`, "m"));
  const sitemap = await (await get("/sitemap.xml")).text();
  assert.doesNotMatch(sitemap, /martinrougeron\.me/, "the sitemap must list the new host");
});

/**
 * The redirect is only safe because the edge hands this Worker exact marketing
 * paths. If `worker_paths` ever grew an API path, the 301 would start answering
 * API calls with "go to a host that has no API on it" — and the failure would
 * be a live outage for the shipped app, not a broken link.
 *
 * The glob ban is already asserted in infra/terraform (variable validation and
 * tests/policy.tftest.hcl). This is the other half: no NAMED API path either.
 */
test("no API path is routed to the Worker", async () => {
  const routed = workerPaths();
  assert.ok(routed.length > 0, "worker_paths did not parse");

  // The origin's own surface, from infra/terraform/cloudflare.tf and the nginx
  // config it fronts. /donate is the marketing page and belongs here; its
  // SUB-paths call Stripe and do not.
  const origin = [
    "/auth",
    "/mqtt",
    "/stripe",
    "/health",
    "/supporters",
    "/donate/checkout",
    "/donate/thanks",
    "/donate/cancelled",
  ];
  for (const path of routed) {
    for (const api of origin) {
      assert.ok(
        path !== api && !path.startsWith(`${api}/`),
        `worker_paths routes ${path}, which the origin serves — on the old host ` +
          "the Worker would answer it with a 301 to a host that has no API",
      );
    }
  }
});

/**
 * Drift guard across the package boundary, same shape as the Stripe-origin one.
 *
 * The app opens /eula, /privacy, /terms and /support in a browser from
 * Deployment.swift. Those are also the URLs App Store Connect fetches.
 *
 * THERE ARE TWO HOSTS, and the whole point of this test is that they are not
 * interchangeable:
 *
 *   api.hqchat.app  the origin the app talks to        — `serverHost`
 *   hqchat.app      the Worker that serves these pages — `siteHost`
 *
 * The apex answers both (the Worker takes the exact marketing paths, everything
 * else falls through to nginx), so pointing the app at it looks fine. `api.`
 * answers only the second: the Worker is not routed there, so a page request
 * gets nginx's REST 404.
 *
 * That is not hypothetical. The two were briefly collapsed into one constant,
 * `siteURL` was derived from `serverHost`, and when the API moved back to
 * `api.` the derivation followed it — silently sending all four in-app legal
 * links, the EULA URL a reviewer opens included, to a 404. Hence: assert the
 * split, in both directions.
 */
test("the app's two hosts are the API and the site, and not each other", async () => {
  const swift = readFileSync(join(REPO, "apps/apple/HQChat/Deployment.swift"), "utf8");

  const host = (name) => swift.match(new RegExp(`static let ${name} = "([^"]+)"`))?.[1];

  // The API. A subdomain of the site's host, never the host itself — the apex
  // would work today and is exactly the arrangement that broke the links above.
  const serverHost = host("serverHost");
  assert.ok(serverHost, "could not read serverHost from Deployment.swift");
  assert.equal(
    `https://${serverHost}`,
    ORIGIN.replace("https://", "https://api."),
    "the app must talk to the api. subdomain, not the apex",
  );

  // The site. The bare host this Worker answers to, and the one every canonical
  // on it names.
  const siteHost = host("siteHost");
  assert.ok(siteHost, "could not read siteHost from Deployment.swift");
  assert.equal(`https://${siteHost}`, ORIGIN, "the app's legal links point at a host this Worker does not serve");

  assert.notEqual(serverHost, siteHost, "the API host and the site host must stay distinct constants");

  // And the derivation has to hang off the SITE host. Deriving it from
  // serverHost is the specific regression this test exists for.
  assert.match(
    swift,
    /siteURL.*https:\/\/\\\(siteHost\)/,
    "siteURL must derive from siteHost — deriving it from serverHost 404s",
  );

  // The retired host — 2.1.0 names it and cannot be told otherwise — must not
  // linger anywhere in the source as a live value.
  assert.doesNotMatch(
    swift,
    /static let \w+ = "hqchat\.martinrougeron\.me"/,
    "the retired host must not be a live constant",
  );

  // Every page the app deep-links to has to be one this Worker actually serves,
  // or the link is a 404 a reviewer finds first.
  for (const m of swift.matchAll(/siteURL\.appendingPathComponent\("([^"]+)"\)/g)) {
    assert.ok(ROUTES.includes(`/${m[1]}`), `Deployment.swift links to /${m[1]}, which this Worker does not serve`);
  }
});
