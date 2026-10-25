/**
 * hqchat — the marketing site, served at the root of hqchat.app.
 *
 * The site and the API are the same host, which is what keeps the donate form
 * a same-origin POST: the Worker takes the exact paths below and everything
 * else falls through to nginx. `serverHost` in
 * apps/apple/HQChat/Deployment.swift names this host too.
 *
 * It moved here from a subdomain of a personal domain, and that move was a
 * BREAKING one — builds already installed carry the old host and cannot be
 * told otherwise. See `CANONICAL_HOST` below for what this Worker does with a
 * request that arrives on any other name.
 *
 * One Cloudflare Worker, no build step, no executable JavaScript, no external
 * assets. Everything below is inlined because the CSP is `default-src 'none'`
 * and widening it for a webfont or an icon would be a poor trade on a page
 * whose entire argument is "we took the careful option". The one <script> on
 * the site is a `type="application/ld+json"` DATA BLOCK: the HTML parser hands
 * it to nobody, it is never executed, and CSP does not gate it — it exists
 * because structured data is the only machine-readable way to tell a search
 * engine that the thing being described is a free iPhone app with a store
 * listing. The favicon is a `data:` SVG for the same reason.
 *
 * Both halves of the product are public — the app and the server, in one
 * repository — and a good deal of the copy below
 * turns on that. Their URLs and the asymmetry in their licensing live in one
 * place; see CLIENT_REPO / SERVER_REPO.
 *
 * Routes (each an EXACT Terraform route — see infra/terraform/cloudflare.tf):
 *   /             the site
 *   /crypto       the long-form protocol write-up
 *   /donate       what it costs, and the ask
 *   /privacy      privacy policy   (App Store requires a public privacy URL)
 *   /terms        terms of service
 *   /eula         the custom EULA given to App Store Connect
 *   /support      support + contact (App Store requires a support URL)
 *   /robots.txt   crawl policy for the WHOLE host, API paths included
 *   /sitemap.xml  the HTML routes above, and nothing the origin serves
 *
 * The visual system is a port of apps/apple/HQChat/Helpers/Theme.swift; the
 * token values and the rules that govern them are documented in
 * docs/product/design-system.md. Two of those rules are load-bearing and easy
 * to break by accident:
 *   - --purple measures 3.22:1 and must never be used for text, only for
 *     borders, fills and glows. Violet text uses --purple-light.
 *   - everything the product draws itself is lowercase.
 */

/* ── Where this site lives, and the one host it admits to ──────────────────
 * hqchat.app is the site's address. Everything that states an address — the
 * canonical, og:url, every <loc> in the sitemap, the Sitemap: line in
 * robots.txt — says so, absolutely: a relative canonical is valid HTML that
 * silently does nothing, which is the worst combination a tag can have.
 *
 * ⚠️ THE OTHER HOSTS. This Worker is also routed on www.hqchat.app, and would
 * answer on any other name the edge ever sends it. A request arriving on one
 * is answered with a 301 here, not with the page — two hosts serving the same
 * markup is the duplicate-content problem a canonical tag only half-solves.
 *
 * That redirect is safe ONLY because the edge routes this Worker to EXACT
 * marketing paths (var.worker_paths). Every request it can possibly see on the
 * old host is a page. The API on that host — /auth, /mqtt, /donate/checkout,
 * /stripe/webhook, /health — never reaches this code and must never be routed
 * to it, or the redirect would start answering API calls with a 301 to a host
 * that has no API on it. Widening those routes to "/*" is the way to cause
 * that, which is the third reason infra/terraform refuses a glob.
 */
const CANONICAL_HOST = "hqchat.app";
const SITE_ORIGIN = `https://${CANONICAL_HOST}`;

/**
 * Hosts where "not canonical" means "not deployed", so the 301 must not fire.
 *
 * `wrangler dev` serves on localhost and a workers.dev preview serves on
 * *.workers.dev; without this carve-out both would answer every path with a
 * redirect to production, and local iteration on the site would consist of
 * watching the browser leave.
 */
const isDevHost = (host) =>
  host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host.endsWith(".workers.dev");

/* ── The app, as the App Store has it ──────────────────────────────────────
 * Shipped 2026-09-16. The listing is called "hqChat" — capital C, because that
 * is the name on the store record and a store record is not ours to lowercase.
 * Everywhere the product speaks for itself it is still "hqchat"; the two are
 * the same app and the legal pages say so in as many words.
 *
 * ⚠️ The App Store listing is the iPhone and iPad app. The macOS build has its
 * own bundle id (`martin.rougeron.DissQus`) and no store record of its own, so
 * nothing on this site may offer this link as a way to get it.
 *
 * APP_STORE_ID is the numeric track id. It appears twice for two different
 * jobs: in the download URL, and in the `apple-itunes-app` meta that draws the
 * Smart App Banner at the top of Safari on iOS. Both need it; neither is
 * derivable from the other.
 */
const APP_STORE_ID = "6786412967";
const APP_STORE_NAME = "hqChat";
const APP_MIN_IOS = "18.5";
const APP_RELEASED = "2026-09-16";

// Where someone actually gets the app. This was empty for as long as there was
// nothing behind it, and the page said so rather than linking at a promise.
const DOWNLOAD_URL = `https://apps.apple.com/app/hqchat/id${APP_STORE_ID}`;

/**
 * ── Donation tiers ────────────────────────────────────────────────────────
 * Labels only: no Stripe price id appears in this file. Each button posts an
 * index (`tier0`, `tier1`, …, or `once`) into the operator's
 * `STRIPE_DONATION_PRICE_IDS`, and the server resolves it
 * (services/server/src/server/donate.ts), so a fork never inherits buttons
 * pointed at someone else's prices.
 *
 * These arrays must have the same length and low-to-high order as the
 * environment's `donations.monthlyPriceIds`; site.test.mjs checks it. The
 * labels are display-only; Stripe is authoritative for what is charged.
 */
const TIERS = [{ label: "€2 / month" }, { label: "€5 / month" }, { label: "€15 / month" }];
// A FIXED amount, not a donor-chosen one. Set `custom_unit_amount` on the Price
// in Stripe if that should change — and change the copy with it, because
// several sentences on this site currently name the number.
const ONE_TIME = { label: "€10 once" };

const CONTACT_EMAIL = "support@martinrougeron.me";

/**
 * ── Where the code is ─────────────────────────────────────────────────────
 * Both halves are public, in one repository: two builds, two toolchains, only
 * the wire format in common. Every link on the site is built from these three
 * constants.
 *
 * ⚠️ Licensing is not symmetric, and nothing on this site may imply it is. The
 * server carries AGPL-3.0; the app carries PolyForm Strict, which makes it
 * source you can read and build, not source licensed for redistribution. The
 * copy says "published" of the app and "AGPL-3.0" of the server, never both
 * together.
 */
const ORG_URL = "https://github.com/HQChat/HQCHAT";
const CLIENT_REPO = `${ORG_URL}/tree/main/apps/apple`;
const SERVER_REPO = `${ORG_URL}/tree/main/services/server`;
const LAST_UPDATED = "October 25, 2026";

/* ── What it costs to run ──────────────────────────────────────────────────
 * Published because the whole argument of this site is that it takes the
 * careful option and says so. A donation page that will not say what the money
 * is for is asking to be trusted about the one thing it could simply show.
 *
 * Figures are monthly and approximate, in USD, and deliberately rounded rather
 * than precise — an exact number here would go stale within a billing cycle and
 * be worse for being wrong. Update them when the bill changes.
 */
const COSTS = [
  ["DigitalOcean droplet — production, London", "$18"],
  ["DigitalOcean droplet — pre-prod", "$18"],
  ["DigitalOcean Managed Postgres (single node)", "$15"],
  ["Apple Developer Program ($99/yr)", "$8"],
  ["Domain", "$1"],
  ["Cloudflare — DNS, the Worker serving this page, R2", "$0"],
  ["Sentry — crash reporting", "$0"],
];
const COSTS_TOTAL = "about $60 a month";

/**
 * Where Stripe Checkout lives, and why this constant exists on a page that
 * never fetches it.
 *
 * The donate buttons POST to /donate/checkout, which answers 302 →
 * checkout.stripe.com. `form-action` is enforced ACROSS THAT REDIRECT, and it
 * is checked against the CSP of the document that submitted the form — this
 * one — not against the CSP of the 302. Omit the Stripe origin here and the
 * browser drops the redirect silently: the server logs a healthy 302, the page
 * simply does not move, and the only evidence is a console line nobody reads.
 *
 * That is not hypothetical; it already happened once. The postmortem is in
 * services/server/src/server/donate.ts, whose CHECKOUT_ORIGIN this must
 * match. It cannot be imported across the package boundary, so test/site.test.mjs
 * reads that file and asserts the two strings are equal. If Checkout ever moves
 * to a custom domain, that test fails instead of the button going quiet.
 */
const CHECKOUT_ORIGIN = "https://checkout.stripe.com";

const CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
  "img-src data:",
  `form-action 'self' ${CHECKOUT_ORIGIN}`,
  "frame-ancestors 'none'",
  "base-uri 'none'",
].join("; ");

/* ── The visual system, ported from Theme.swift ──────────────────────────── */

const CSS = `
:root{
  --bg-top:#101116; --bg-bottom:#16171d; --screen:#070809; --panel:#0a0b10;
  --green:#16c46e; --green-bright:#1bd676; --green-deep:#0f7d49; --green-pale:#7fe6b0;
  --purple:#7b2ff7; --purple-light:#a06bff;
  --warning:#ffb23b; --danger:#ff5a3c; --danger-light:#ff8a72;
  --text-primary:#eef0f3; --text-second:#9a9ca6; --text-dim:#8b8d96; --text-faint:#83858f;
  --text-on-card:#cdcfd6; --on-green:#06140c;
  --hairline:rgba(255,255,255,.08); --fill-soft:rgba(255,255,255,.04);
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --ui:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}

/* The app has one appearance. No prefers-color-scheme block, and body paints an
   explicit ground so nothing shows through from the host. */
html{background:var(--bg-top)}
body{
  margin:0; background:linear-gradient(180deg,var(--bg-top) 0%,var(--bg-bottom) 100%);
  color:var(--text-primary); font-family:var(--mono); font-size:14px; line-height:1.6;
  min-height:100vh; position:relative; overflow-x:hidden;
  -webkit-font-smoothing:antialiased;
}

/* HQScreenBackground, layer for layer: two blurred bokeh glows and a vignette
   here, scanlines above. Both are inert to the pointer. */
body::before{
  content:""; position:fixed; inset:0; z-index:0; pointer-events:none;
  background:
    radial-gradient(circle at 12% 8%, rgba(22,196,110,.42) 0, transparent 220px),
    radial-gradient(circle at 92% 95%, rgba(123,47,247,.42) 0, transparent 220px),
    radial-gradient(circle at 50% 50%, transparent 120px, rgba(0,0,0,.65) 520px);
  filter:blur(90px) saturate(1.1);
  animation:drift 11s ease-in-out infinite alternate;
}
body::after{
  content:""; position:fixed; inset:0; z-index:0; pointer-events:none;
  background:repeating-linear-gradient(to bottom,rgba(0,0,0,.30) 0 1px,transparent 1px 3px);
  opacity:.62; mix-blend-mode:multiply;
}
@keyframes drift{from{transform:scale(1)}to{transform:scale(1.08)}}
@keyframes blink{from{opacity:1}to{opacity:.15}}

/* Every perpetual animation in the app checks accessibilityReduceMotion. */
@media (prefers-reduced-motion:reduce){
  body::before{animation:none}
  .cursor{animation:none}
  *{transition:none !important}
}

.wrap{position:relative; z-index:1; max-width:880px; margin:0 auto; padding:0 20px 80px}

/* ── the prompt, and the bar it sits in ─────────────────────────────────── */
.bar{
  position:relative; z-index:2; background:var(--screen);
  border-bottom:1px solid var(--hairline); padding:10px 20px;
  display:flex; align-items:center; gap:14px; flex-wrap:wrap;
}
.prompt{font-size:15px; white-space:nowrap}
.prompt b{color:var(--green); font-weight:700}
.prompt .p{color:var(--text-dim)}
.prompt .seg{color:var(--purple-light); font-weight:600}
.cursor{color:var(--green); animation:blink .5s ease-in-out infinite alternate}
.bar nav{margin-left:auto; display:flex; gap:14px; flex-wrap:wrap}
.bar nav a{color:var(--text-dim); text-decoration:none; font-size:12px}
.bar nav a:hover{color:var(--green)}

.chip{
  display:inline-flex; align-items:center; gap:7px; border:1px solid rgba(255,255,255,.35);
  padding:4px 8px; font-size:10.5px; letter-spacing:.1em; text-transform:uppercase;
  color:var(--text-second);
}
.chip i{width:6px; height:6px; border-radius:50%; background:var(--green);
        box-shadow:0 0 4px rgba(22,196,110,.9)}

/* ── sections read as shell exchanges ───────────────────────────────────── */
.sec{margin:0 0 8px; padding:34px 0 6px}
.cmd{font-size:13px; color:var(--text-second); margin:0 0 18px; word-break:break-word}
.cmd::before{content:"$ "; color:var(--green); font-weight:700}
.cmd em{color:var(--purple-light); font-style:normal}
.note{color:var(--text-faint); font-size:12px}
.note::before{content:"# "; color:var(--green-deep)}

/* A bare URL in mono is ~350px wide and will push a 320px viewport sideways.
   'anywhere' is the only value that also shrinks min-content, which is what a
   grid track measures — so links get it and prose does not, since 'anywhere' in
   a narrow table cell hyphenates ordinary words mid-syllable. Table cells need
   nothing: the table sits in a .scroll with its own min-width. */
a{overflow-wrap:anywhere}
p,li,.cmd,.note{overflow-wrap:break-word}

h1,h2,h3{font-weight:700; letter-spacing:-.01em; margin:0 0 10px; text-transform:lowercase}
h1{font-size:26px} h2{font-size:19px} h3{font-size:15px}
p{margin:0 0 14px; color:var(--text-on-card); max-width:66ch}
.ui{font-family:var(--ui); line-height:1.65}
a{color:var(--green)}
strong{color:var(--text-primary)}
code{color:var(--green-pale); font-size:.92em}

.lbl{
  display:block; font-size:10.5px; font-weight:600; letter-spacing:.18em;
  text-transform:uppercase; color:var(--text-dim); margin:0 0 8px;
}
hr{border:0; border-top:1px dashed var(--hairline); margin:30px 0}

/* ── cards, squares and hairlines. radius 0 is the default in the app. ──── */
.card{
  position:relative; background:var(--fill-soft); border:1px solid var(--hairline);
  padding:16px 18px; margin:0 0 14px;
}
.card.acc{background:rgba(22,196,110,.05); border-color:rgba(22,196,110,.40)}
.card.acc::after{
  content:""; position:absolute; left:-1px; top:-1px; bottom:-1px; width:2px;
  background:var(--green); box-shadow:0 0 4px rgba(22,196,110,.7);
}
.card.vio{background:rgba(123,47,247,.05); border-color:rgba(123,47,247,.40)}
.card.warn{background:rgba(255,178,59,.05); border-color:rgba(255,178,59,.35)}

/* CornerBrackets: four 11px green L's, 2px stroke. Two on the card, two on the
   empty <i> it carries, because a box only has two pseudo-elements. */
.brk::before,.brk::after,.brk i::before,.brk i::after{
  content:""; position:absolute; width:11px; height:11px; border:2px solid var(--green);
}
.brk::before{top:-1px; left:-1px; border-right:0; border-bottom:0}
.brk::after{bottom:-1px; right:-1px; border-left:0; border-top:0}
.brk i::before{top:-1px; right:-1px; border-left:0; border-bottom:0}
.brk i::after{bottom:-1px; left:-1px; border-right:0; border-top:0}

/* ── wide things scroll inside themselves, never the page ───────────────── */
.scroll{overflow-x:auto; -webkit-overflow-scrolling:touch; margin:0 0 16px;
        border:1px solid var(--hairline); background:rgba(0,0,0,.35)}
pre{margin:0; padding:16px 18px; font-family:var(--mono); font-size:12px;
    line-height:1.55; color:var(--text-second); white-space:pre}
pre b{color:var(--green); font-weight:600}
pre u{color:var(--purple-light); text-decoration:none}
pre s{color:var(--text-faint); text-decoration:none}

table{border-collapse:collapse; width:100%; font-size:12.5px; min-width:520px}
th,td{border:1px solid var(--hairline); padding:8px 12px; text-align:left; vertical-align:top}
th{color:var(--text-dim); font-weight:600; letter-spacing:.1em; text-transform:uppercase;
   font-size:10.5px; background:rgba(255,255,255,.02)}
td{color:var(--text-on-card)}
td b{color:var(--text-primary)}
.yes{color:var(--green)} .no{color:var(--danger-light)}

/* The monthly bill. Overrides the global table rules deliberately: this one
   lives inside a card and in a grid column, so the 520px floor that keeps the
   comparison tables readable would force a scrollbar on a two-column list of
   short lines. Borderless for the same reason — it is a receipt, not a matrix. */
table.costs{min-width:0; font-size:12.5px; margin:0 0 12px}
table.costs td{border:0; border-bottom:1px solid var(--hairline); padding:6px 0}
table.costs tr:last-child td{border-bottom:0}
table.costs td:last-child{text-align:right; white-space:nowrap; padding-left:14px;
   color:var(--text-primary)}

ul{margin:0 0 14px; padding-left:20px; color:var(--text-on-card); max-width:66ch}
li{margin:6px 0}
ul.bare{list-style:none; padding-left:0}
ul.bare li::before{content:"— "; color:var(--green-deep)}

/* ── the button ─────────────────────────────────────────────────────────── */
form{margin:18px 0 10px; display:flex; flex-wrap:wrap; gap:10px}
button{
  font-family:var(--mono); font-size:15px; font-weight:700; letter-spacing:.02em;
  color:var(--on-green); background:linear-gradient(135deg,var(--green-bright),var(--green-deep));
  border:1px solid rgba(22,196,110,.75); box-shadow:0 2px 14px rgba(22,196,110,.5);
  border-radius:0; height:48px; padding:0 26px; cursor:pointer;
  /* Was min-width:220px, for one button on its own line. Four of them in a
     flex row need to shrink instead, or the tiers overflow a grid column. */
  min-width:132px; flex:1 1 auto;
}
button:hover{filter:brightness(1.06)}
button:active{opacity:.7}
button:focus-visible{outline:2px solid var(--green-pale); outline-offset:3px}
.price{color:var(--text-primary); font-weight:700}

/* The App Store link wears the button, but it is an <a>: it navigates, it
   submits nothing, and a <form> wrapped round it purely for the styling would
   put a second form on a page whose only real one posts money. Everything here
   is copied from the button rule above rather than shared, because a
   comma-joined selector would drag the <a> into the flex row the tiers
   live in. */
.btn{
  display:inline-flex; align-items:center; justify-content:center;
  font-family:var(--mono); font-size:15px; font-weight:700; letter-spacing:.02em;
  color:var(--on-green); text-decoration:none;
  background:linear-gradient(135deg,var(--green-bright),var(--green-deep));
  border:1px solid rgba(22,196,110,.75); box-shadow:0 2px 14px rgba(22,196,110,.5);
  height:48px; padding:0 26px; min-width:132px;
}
.btn:hover{filter:brightness(1.06)}
.btn:active{opacity:.7}
.btn:focus-visible{outline:2px solid var(--green-pale); outline-offset:3px}
.cta{margin:20px 0 4px; max-width:none}
.cta .sub{display:block; margin:8px 0 0}

/* ── hero ───────────────────────────────────────────────────────────────── */
.hero{padding:52px 0 10px}
.mark{
  width:56px; height:56px; border-radius:11.8px; background:var(--panel);
  border:1px solid rgba(255,255,255,.06); display:grid; grid-template-columns:repeat(3,1fr);
  gap:2px; padding:10px; margin:0 0 20px;
}
.mark span{background:rgba(255,255,255,.07); border-radius:1.5px}
.mark span.g{background:radial-gradient(circle at 42% 36%,#fff,var(--green));
             box-shadow:0 0 5px rgba(22,196,110,.9)}
.mark span.v{background:radial-gradient(circle at 42% 36%,#fff,var(--purple));
             box-shadow:0 0 5px rgba(123,47,247,.9)}
.word{font-family:var(--ui); font-size:34px; letter-spacing:-.03em; color:#fff; margin:0 0 6px}
.word span{font-weight:300} .word strong{font-weight:700}
.tag{font-size:11px; letter-spacing:.18em; text-transform:lowercase; color:var(--text-dim);
     margin:0 0 22px}
.lede{font-family:var(--ui); font-size:16px; color:var(--text-on-card); max-width:60ch}

/* ── the deliberately uneven bit ────────────────────────────────────────── */
.grid{display:grid; grid-template-columns:1.35fr .95fr; gap:14px; align-items:start}
.grid.flip{grid-template-columns:.85fr 1.4fr}
@media (max-width:720px){
  .grid,.grid.flip{grid-template-columns:1fr}
  .wrap{padding:0 14px 60px}
  .word{font-size:28px}
  .bar nav{margin-left:0; width:100%}
}
.indent{margin-left:24px}
@media (max-width:720px){.indent{margin-left:0}}

footer{border-top:1px dashed var(--hairline); margin-top:40px; padding-top:22px;
       color:var(--text-faint); font-size:12px}
footer a{color:var(--text-dim); text-decoration:none}
footer a:hover{color:var(--green)}

/* ── legal pages: prose, still on the terminal ground ───────────────────── */
.doc{max-width:72ch}
.doc h2{font-size:15px; margin:28px 0 8px; color:var(--green-pale)}
.doc p,.doc li{font-family:var(--ui); color:var(--text-on-card)}
.updated{color:var(--text-faint); font-size:12px; margin:0 0 26px}
`;

/* ── components ──────────────────────────────────────────────────────────── */

/**
 * The 3x3 mark: two lit cells, green top-right and violet bottom-left.
 * Decorative (`aria-hidden`): the wordmark beside it is the <h1>.
 */
const MARK = `<div class="mark" aria-hidden="true">
  <span></span><span></span><span class="g"></span>
  <span></span><span></span><span></span>
  <span class="v"></span><span></span><span></span>
</div>`;

/**
 * The wordmark, and the home page's <h1>.
 *
 * It was a <div> until the app shipped, which left the front page with no
 * top-level heading — an accessibility gap first and an SEO one second. The
 * `.word` rules outrank the bare `h1` selector on specificity, so the type
 * scale is unchanged; the two <span>s still carry the weights.
 */
const WORDMARK = `<h1 class="word"><span>hq</span><strong>chat</strong></h1>`;

/** hqchat:~/<path>$ █ — the prompt every screen in the app wears. */
const prompt = (path) =>
  `<span class="prompt"><b>hqchat</b><span class="p">:~/</span>` +
  `<span class="seg">${path}</span><span class="p">$</span> <span class="cursor">█</span></span>`;

const bar = (path) => `<div class="bar">${prompt(path)}
  <span class="chip"><i></i>secure</span>
  <nav><a href="/">home</a><a href="${DOWNLOAD_URL}">app store</a><a href="/crypto">crypto</a><a href="/donate">donate</a>
  <a href="${ORG_URL}">source</a>
  <a href="/privacy">privacy</a><a href="/terms">terms</a><a href="/eula">eula</a><a href="/support">support</a></nav>
</div>`;

/** A section, written as a shell command and its output. */
const sec = (cmd, body) => `<section class="sec"><p class="cmd">${cmd}</p>${body}</section>`;

const scroll = (inner) => `<div class="scroll">${inner}</div>`;

/**
 * Attribute escaping, for the one place on this site where copy is interpolated
 * into an attribute rather than into element content. Every meta description
 * below is a sentence written by hand, so the practical job is the apostrophe
 * and the ampersand — but a description that grew a quote would otherwise end
 * the attribute and put prose into the tag, and that is not a bug worth
 * discovering in a search result.
 */
const attr = (v) =>
  String(v).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/**
 * Structured data, on the home page only.
 *
 * This is what tells a search engine that the subject of the page is a free
 * iOS application with a store listing, rather than inferring it from prose.
 * It is a `type="application/ld+json"` data block: the HTML parser does not
 * execute it, CSP does not gate it, and the site still runs no JavaScript.
 *
 * Two things are deliberately ABSENT, and both are absent for the same reason —
 * structured data that overstates is worse than none:
 *   - `aggregateRating`. The listing has no ratings yet. Inventing one is the
 *     single most penalised thing you can put in this block.
 *   - `softwareVersion`. It changes with every release and nothing here would
 *     notice, so the page would quietly advertise a stale one forever.
 *
 * `<` is escaped so no value can ever close the element early.
 */
const JSON_LD = `<script type="application/ld+json">${JSON.stringify({
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebSite",
      "@id": `${SITE_ORIGIN}/#website`,
      url: `${SITE_ORIGIN}/`,
      name: "hqchat",
      inLanguage: "en",
      publisher: { "@id": `${SITE_ORIGIN}/#author` },
    },
    {
      "@type": "Person",
      "@id": `${SITE_ORIGIN}/#author`,
      name: "Martin Rougeron",
      url: `${SITE_ORIGIN}/`,
    },
    {
      "@type": "MobileApplication",
      "@id": `${SITE_ORIGIN}/#app`,
      name: APP_STORE_NAME,
      alternateName: "hqchat",
      applicationCategory: "SocialNetworkingApplication",
      operatingSystem: `iOS ${APP_MIN_IOS} or later`,
      url: `${SITE_ORIGIN}/`,
      downloadUrl: DOWNLOAD_URL,
      installUrl: DOWNLOAD_URL,
      datePublished: APP_RELEASED,
      isAccessibleForFree: true,
      author: { "@id": `${SITE_ORIGIN}/#author` },
      offers: {
        "@type": "Offer",
        price: "0",
        priceCurrency: "EUR",
        availability: "https://schema.org/InStock",
      },
      featureList: [
        "post-quantum HQC-256 key agreement",
        "AES-256-GCM message encryption",
        "no phone number, no email address, no account",
        "safety numbers and QR key verification",
        "published source for the app and the server",
        "AGPL-3.0 server you can run yourself",
        "opt-in AI replies from the helper account (Claude Haiku, by Anthropic)",
      ],
      privacyPolicy: `${SITE_ORIGIN}/privacy`,
    },
  ],
}).replace(/</g, "\\u003c")}</script>`;

/**
 * Every page's head.
 *
 * `path` does double duty — it is the segment the prompt draws in the bar AND
 * the URL the canonical points at — which is exactly what you want, because the
 * two drifting apart is how a page ends up declaring itself canonical at
 * something else.
 *
 * `desc` is per page and required. One description reused across seven pages is
 * how a site tells a crawler its pages are duplicates of each other, and this
 * site shipped that way until the app did.
 */
const shell = ({ title, path, desc, indexable = true }, inner) => {
  const url = `${SITE_ORIGIN}/${path}`;
  const full = `${title} · hqchat`;
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${full}</title>
<meta name="description" content="${attr(desc)}">
<meta name="robots" content="${indexable ? "index, follow, max-image-preview:large" : "noindex, follow"}">
${
  indexable
    ? `<link rel="canonical" href="${url}">
`
    : ""
}<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1024 1024'%3E%3Cdefs%3E%3CradialGradient id='a' cx='.3' cy='.28' r='.6'%3E%3Cstop stop-color='%2316c46e' stop-opacity='.35'/%3E%3Cstop offset='1' stop-color='%2316c46e' stop-opacity='0'/%3E%3C/radialGradient%3E%3CradialGradient id='b' cx='.72' cy='.72' r='.6'%3E%3Cstop stop-color='%237b2ff7' stop-opacity='.4'/%3E%3Cstop offset='1' stop-color='%237b2ff7' stop-opacity='0'/%3E%3C/radialGradient%3E%3CradialGradient id='c' cx='.4' cy='.38' r='.65'%3E%3Cstop stop-color='%23f2fff8'/%3E%3Cstop offset='.45' stop-color='%235fe39f'/%3E%3Cstop offset='1' stop-color='%2316c46e'/%3E%3C/radialGradient%3E%3CradialGradient id='d' cx='.4' cy='.38' r='.65'%3E%3Cstop stop-color='%23f7f0ff'/%3E%3Cstop offset='.45' stop-color='%23a06bfa'/%3E%3Cstop offset='1' stop-color='%237b2ff7'/%3E%3C/radialGradient%3E%3ClinearGradient id='e' x2='0' y2='1'%3E%3Cstop stop-color='%23fff' stop-opacity='.07'/%3E%3Cstop offset='1' stop-color='%23fff' stop-opacity='.02'/%3E%3C/linearGradient%3E%3Cfilter id='f' x='-.5' y='-.5' width='2' height='2'%3E%3CfeGaussianBlur stdDeviation='28'/%3E%3C/filter%3E%3C/defs%3E%3Crect width='1024' height='1024' fill='%23070809'/%3E%3Crect width='1024' height='1024' fill='url(%23a)'/%3E%3Crect width='1024' height='1024' fill='url(%23b)'/%3E%3Cpath d='M341 0V1024M682 0V1024M0 341H1024M0 682H1024' stroke='%23fff' stroke-opacity='.05' stroke-width='2'/%3E%3Cg fill='url(%23e)' stroke='%23fff' stroke-opacity='.08' stroke-width='2'%3E%3Crect x='222' y='222' width='164' height='164' rx='14'/%3E%3Crect x='430' y='222' width='164' height='164' rx='14'/%3E%3Crect x='222' y='430' width='164' height='164' rx='14'/%3E%3Crect x='430' y='430' width='164' height='164' rx='14'/%3E%3Crect x='638' y='430' width='164' height='164' rx='14'/%3E%3Crect x='430' y='638' width='164' height='164' rx='14'/%3E%3Crect x='638' y='638' width='164' height='164' rx='14'/%3E%3C/g%3E%3Crect x='638' y='222' width='164' height='164' rx='14' fill='%2316c46e' opacity='.8' filter='url(%23f)'/%3E%3Crect x='638' y='222' width='164' height='164' rx='14' fill='url(%23c)'/%3E%3Crect x='222' y='638' width='164' height='164' rx='14' fill='%237b2ff7' opacity='.8' filter='url(%23f)'/%3E%3Crect x='222' y='638' width='164' height='164' rx='14' fill='url(%23d)'/%3E%3C/svg%3E">
<meta name="color-scheme" content="dark"><meta name="theme-color" content="#101116">
<meta name="apple-itunes-app" content="app-id=${APP_STORE_ID}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="hqchat">
<meta property="og:locale" content="en_US">
<meta property="og:title" content="${attr(full)}">
<meta property="og:description" content="${attr(desc)}">
${
  indexable
    ? `<meta property="og:url" content="${url}">
`
    : ""
}<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${attr(full)}">
<meta name="twitter:description" content="${attr(desc)}">
${path === "" ? `${JSON_LD}\n` : ""}<style>${CSS}</style>
</head><body>${bar(path)}<div class="wrap">${inner}${FOOTER}</div></body></html>`;
};

const FOOTER = `<footer>
  <p><a href="${DOWNLOAD_URL}">app store</a> · <a href="/privacy">privacy</a> · <a href="/terms">terms</a>
  · <a href="/eula">eula</a> · <a href="/support">support</a>
  · <a href="${CLIENT_REPO}">app source</a> · <a href="${SERVER_REPO}">server source</a>
  · <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a></p>
  <p>the app's source is published; the server is AGPL-3.0. the apps are for iOS and macOS.</p>
</footer>`;

/**
 * The donate control. A plain cross-document form POST to the origin's
 * /donate/checkout, which is same-origin with this page — the Worker and the
 * API answer on the same host, and /donate/* below the bare path is not a
 * Worker route (infra/terraform/cloudflare.tf).
 *
 * There are still no inputs. Stripe collects everything at checkout, including
 * the optional name for the supporters page, so nothing anyone types about
 * themselves passes through our server
 * (services/server/src/server/donate.ts).
 */
const DONATE_FORM = `<form method="POST" action="/donate/checkout">
  ${TIERS.map((t, i) => `<button type="submit" name="choice" value="tier${i}">${t.label}</button>`).join("")}
  <button type="submit" name="choice" value="once">${ONE_TIME.label}</button>
</form>`;

const donateNote = () =>
  `<p class="note">a donation buys nothing — everyone has the whole app either way.
   stripe takes it from here; there is nothing to fill in on this site.</p>`;

/**
 * The install block.
 *
 * It said "not shipped yet" for as long as that was true, which is the only
 * reason the sentence it says now is worth anything. Two things it is careful
 * about, both of which a launch usually gets wrong:
 *   - it names the DEVICES, because the listing is the iPhone and iPad app and
 *     the rest of this site says "iOS and macOS" of the software itself;
 *   - it says free WITHOUT saying "free tier", because there are no tiers.
 */
const downloadBlock = () =>
  DOWNLOAD_URL
    ? `<div class="card acc"><span class="lbl">get the app</span>
       <p><a class="btn" href="${DOWNLOAD_URL}">${APP_STORE_NAME} on the app store</a></p>
       <p class="note">free, for iPhone and iPad, iOS ${APP_MIN_IOS} or later. every feature is
       in it and there is nothing to buy anywhere inside it. the App Store listing is the iOS
       app; the macOS build is not on the store.</p></div>`
    : `<div class="card warn"><span class="lbl">not shipped yet</span>
       <p>hqchat is not on the App Store or TestFlight yet, so there is currently nothing to
       install. Donating now funds the work that gets it there; it does not reserve you
       anything, because there is nothing to reserve — the app is free when it lands.
       If you would rather wait until you can actually run it, do. Come back.</p></div>`;

/* ── diagrams ────────────────────────────────────────────────────────────── */

/** Mutual encapsulation. Not a Diffie–Hellman, and there is no initiator. */
const HANDSHAKE = `<pre>  alice                        <s># bob can be offline until the challenge</s>           bob
    │                                                                              │
    │  <b>1.</b> fetch bob's identity key, and <u>CHECK sha256(pk) == the id you have</u>        │
    │     <s># a substituted key produces no session, not a wrong one</s>                 │
    │                                                                              │
    │  <b>2.</b> claim a prekey bundle <b>{medium_pk, onetime_pk?}</b>                           │
    │                                                                              │
    │  <b>3.</b> encapsulate to ALL of them                                               │
    │       (ct_id, ss_id) = <b>Encap(identity_pk)</b>   <s># only bob can decapsulate</s>       │
    │       (ct_mt, ss_mt) = <b>Encap(medium_pk)</b>     <s># forward secrecy, 7-day window</s>  │
    │       (ct_ot, ss_ot) = <b>Encap(onetime_pk)</b>    <s># forward secrecy, single use</s>    │
    │                                                                              │
    │  <b>root₀ = HKDF(ss_id ‖ ss_mt ‖ ss_ot?, "hqchat/v2/init/root")</b>                 │
    │                                                                              │
    │  ── <b>init</b> {ct_id, ct_mt, ct_ot?, rk, senderPk} + a sealed message ────────▶   │
    │       <s>to</s> <u>u/bob/inbox</u> <s>— queued by the broker until he connects</s>                │
    │                                                     <u>CHECK sha256(senderPk)</u>   │
    │                                                     decapsulate all three    │
    │                                                     derive the same root₀    │
    │                                                     <b>and then HOLD it</b>         │
    │                                                                              │
    │  ◀────────── <b>challenge</b> {nonce} <s>on</s> <u>h/{hash}</u> <s>— 60s to answer</s> ───────────────   │
    │       <s># ct_c = Encap(alice's identity_pk): only alice can decapsulate</s>        │
    │                                                                              │
    │  <b>proof = HKDF(ss_c, "hqchat/handshake/v2" ‖ nonce ‖ bob_id ‖ alice_id ‖ T)</b>   │
    │       <s># T = SHA-256 of the init: binds the proof to that one init</s>            │
    │                                                                              │
    │  ────────────────────────── <b>proof</b> ───────────────────────────────────────▶   │
    │                                                     constant-time compare,   │
    │                                                     <b>now</b> accept the init      │
    │                                                                              │
    ▼                                                                              ▼

  three secrets, not one. the server can withhold a one-time key and force the
  medium-term fallback — that shortens a forward-secrecy window. it cannot
  substitute the identity key, because your <b>id is a hash of it</b>.

  HQC is a KEM, not a signature scheme, so prekeys cannot be signed. following
  PQXDH they do not need to be: a substituted prekey yields nothing without
  ss_id, which is why there is no post-quantum signature scheme in the build.</pre>`;

/** A KEM ratchet: root chain stepped by encapsulation, symmetric chain per message. */
const RATCHET = `<pre>  <b>the root chain</b> — steps on a direction flip
  ┌────────────────────────────────────────────────────────────────────────────┐
  │  <b>(root', ck) = HKDF(root ‖ ss, "hqchat/v2/root")</b>                           │
  │                                                                            │
  │  the new root depends on the old one. someone who learns the state at      │
  │  step n cannot run it <s>backwards</s>; someone who missed a step cannot rejoin   │
  │  from later ciphertexts alone.                                             │
  └────────────────────────────┬───────────────────────────────────────────────┘
                               │   <s># a DH ratchet cannot be transliterated: with a</s>
                               │   <s># KEM the encapsulator picks the secret, so a step</s>
                               │   <s># carries a fresh ratchet key AND a ciphertext</s>
          ┌────────────────────┘
          │
  <b>the message chain</b> — every message
          │
          ├─ msg 0   mk = <b>HKDF(ck,"msg")</b> ──▶ AES-256-GCM ──▶ ck = <b>HKDF(ck,"ck")</b>
          ├─ msg 1   mk = <b>HKDF(ck,"msg")</b> ──▶ AES-256-GCM ──▶ ck = <b>HKDF(ck,"ck")</b>
          ├─ msg 2   ...                                    <s>the old ck is destroyed</s>
          ▼
    one-way. a device seized at message 40 cannot work backwards to message 3.

  <b>when it steps.</b> a step costs a public key (7237 B) plus a ciphertext
  (14421 B) — <b>21658 B</b> of key material, which v2 spells as about 29 kB of base64
  and v3 sends as itself. stepping on every flip is strongest and is what Signal
  does; on a phone that is a step per turn. so a flip steps when the chain has run
  <b>32 messages</b> or lived <b>15 minutes</b>, whichever comes first — and always on the
  responder's first reply, where the ratchet actually starts turning. a chain that
  has sent nothing is never stepped off: there is nothing on it to rotate away from.

  <s># the clock was 60 seconds until september 2026, and that was tuned for a fast</s>
  <s># exchange, where a step is nearly free. in the pattern messaging actually has —</s>
  <s># replies minutes apart — EVERY message crossed the threshold and carried a full</s>
  <s># step: a 40-character message that should be a ~300-byte frame became a ~29 kB</s>
  <s># one. at 15 minutes a chain steps on VOLUME inside a conversation and on</s>
  <s># ELAPSED TIME between them, which is the shape the cost profile wants.</s>

  those two numbers <s>are</s> the post-compromise-security window: at most <b>32 messages</b>,
  or <b>15 minutes</b> of an idle conversation, before a compromise heals. widening
  either widens that window. they are not tuning knobs picked for feel.</pre>`;

/** The v3 frame: the canonical header is the frame's own prefix, so it IS the AAD. */
const WIRE = `<pre>  <s><b>v2</b> — JSON carrying base64, and a SECOND encoding beside it</s>
  ┌────────────────────────────────────────────────────────────────────────────┐
  │  <s>{"v":2,"t":"msg","sender":"64 hex","cid":"32 hex","n":7,…}</s>                │
  │                                                                            │
  │  <s>the AAD was not this text. it was a netstring of a fixed field order,</s>    │
  │  <s>written by hand twice — once in Swift, once in TypeScript — beside a</s>     │
  │  <s>JSON encoding produced by two different libraries.</s>                       │
  │                                                                            │
  │  <b>deleted.</b> nothing reads it. a v2 frame is now refused like any other     │
  │  non-frame — which is what makes the recipient binding below mean          │
  │  anything, since an attacker avoiding it could just have sent v2.         │
  └────────────────────────────────────────────────────────────────────────────┘

  <b>the frame</b> — length-prefixed binary. all integers big-endian.
  ┌────────────────────────────────────────────────────────────────────────────┐
  │   0   magic      4 B    "HQCE"                                             │
  │   4   version    u8     3          <s># inside the AAD: a downgrade cannot be</s> │
  │   5   kind       u8     0 msg / 1 init                    <s># spelled</s>        │
  │   6   flags      u8     bit0 rk · bit1 kemCt · bit2 one-time               │
  │   7   sender     32 B   the client id, RAW  <s># v2 spent 64 characters</s>       │
  │  39   <b>to</b>         32 B   the RECIPIENT's client id — new in v3              │
  │  71   cid        16 B   the chain selector, raw                            │
  │  87   n          u32                                                       │
  │  91   pn         u32                                                       │
  │  95   msgIdLen   u8     1..128                                             │
  │  96   msgId      msgIdLen B, UTF-8                                         │
  │       [rk]       u32 len + bytes      [kemCt]  u32 len + bytes             │
  │       [init]     u32 len + senderPk, ctId, ctMt                            │
  │       [oneTime]  u32 len + ctOt, u32 otId                                  │
  ├────────────────────────────────────────────────────────────────────────────┤
  │       <u>── the header ends here; everything above IS the AAD ──</u>              │
  ├────────────────────────────────────────────────────────────────────────────┤
  │       payload    u32 len + ciphertext                                      │
  └────────────────────────────────────────────────────────────────────────────┘

  a receiver binds <b>frame.subarray(0, headerLength)</b> — the literal bytes that
  arrived. there is no second encoding, so there is nothing to keep in step.</pre>`;

/** REST for who you are, MQTT for what you say. Nothing else. */
const TOPOLOGY = `<pre>   iOS / macOS app
        │
        ├── <b>REST over TLS</b> ──────▶  auth + app-api  ──▶  postgres
        │    <s>who you are, who you talk to: handshake, username, friend graph</s>
        │
        └── <b>MQTT over WSS</b> ──────▶  EMQX broker
             <s>the conversations themselves — ciphertext only</s>
                                   │
                                   ├──▶ <u>cv/{random}</u>     the conversation, both members
                                   ├──▶ <u>u/{id}/inbox</u>    first contact, queued while offline
                                   ├──▶ <u>hs/{random}</u>     the challenge that authenticates it
                                   ├──▶ <u>u/{id}/graph</u>    "your friend list changed", nothing more
                                   │
                                   ├──▶ static ACL, <b>no wildcards</b>: a conversation id is its key
                                   └──▶ push-bridge ──▶ APNs ──▶ your device
                                        <s>sees a topic id, sends "New message"</s>

   two protocols, no third. the broker holds undelivered ciphertext in its own
   QoS-1 session — up to 1000 messages, for two hours offline — and nothing
   else does; there is no message table anywhere.</pre>`;

/* ── shared prose blocks, used on / and on /crypto ───────────────────────── */

const PRIMITIVES_TABLE = scroll(`<table>
<thead><tr><th>role</th><th>primitive</th><th>detail</th></tr></thead>
<tbody>
<tr><td>key agreement</td><td><b>HQC-256</b></td>
    <td>code-based KEM, NIST level 5. public key 7237 B · ciphertext 14421 B · shared secret 32 B.
        IND-CCA2, constant-time decapsulation with masked implicit rejection — a malformed
        ciphertext yields a pseudo-random secret rather than an error, so there is no
        decryption oracle to probe.</td></tr>
<tr><td>message encryption</td><td><b>AES-256-GCM</b></td>
    <td>12-byte random nonce, 16-byte tag, authenticated.</td></tr>
<tr><td>key derivation</td><td><b>HKDF-SHA-256</b></td>
    <td>32-byte outputs, domain-separated by <code>info</code>:
        <code>hqchat/v2/init/root</code>, <code>hqchat/v2/init/chain</code>,
        <code>hqchat/v2/root</code>, <code>hqchat/v2/chain</code>, <code>hqchat/v2/msg</code>,
        <code>hqchat/v2/ck</code> for the ratchet; <code>auth</code> for the server
        challenge and <code>hqchat/handshake/v2</code> for the peer one, so the two proofs
        can never be confused.</td></tr>
<tr><td>hashing</td><td><b>SHA-256</b></td>
    <td>topic derivation, safety numbers, and the hashes that stand in for tokens and
        email addresses in the database.</td></tr>
<tr><td>signatures</td><td><b>none</b></td>
    <td>authentication is a KEM challenge–response, not a signature scheme.</td></tr>
</tbody></table>`);

const NOT_HYBRID = `<div class="card vio">
  <span class="lbl">the part most products would not print</span>
  <p><strong>This is not a hybrid.</strong> The message layer is pure HQC — there is no
  X25519, no ML-KEM and no elliptic-curve exchange folded into the shared secret. Most
  post-quantum deployments ship a hybrid precisely so that a break in the new, less-studied
  algorithm still leaves a classical one standing. hqchat does not have that fallback.</p>
  <p>TLS sits underneath, but it is a separate layer rather than a composed one, and it is
  terminated at the edge rather than end-to-end — so it protects the hop, not the message.
  If HQC falls, the message layer falls. That is the honest shape of the trade, and you
  should weigh it before trusting this with anything that matters.</p>
</div>`;

const SERVER_TABLE = scroll(`<table>
<thead><tr><th>what the server holds</th><th>and what that means</th></tr></thead>
<tbody>
<tr><td class="no">✗ your messages</td>
    <td>Bodies are AES-256-GCM under keys derived on the two devices; no server component
        holds those keys or ever has. Nothing is stored server-side —
        undelivered ciphertext sits in the broker's own session, in memory: at most
        1000 messages, kept while you have been offline for under two hours.
        Past either limit the broker drops them, oldest first.
        <b>One exception, and it is yours to make:</b> if you report a message, your copy
        of that one message is uploaded with the report, and deleted after 90 days. The
        app says so on the screen where you send it. Nothing else moves a message body
        off your device, and nothing can do it without you.</td></tr>
<tr><td class="no">✗ the key exchange</td>
    <td>The HQC encapsulations travel inside the conversation topic, which the server routes
        but cannot open.</td></tr>
<tr><td class="no">✗ your email address</td>
    <td>Not in any form. This row used to say the database held
        <code>sha256(lowercased email)</code> to identify subscribers; the paywall it served
        is gone, and no address now reaches this server hashed or otherwise. Stripe holds
        what it needs to take a donation, and it is the only party that does.</td></tr>
<tr><td class="no">✗ your private keys</td>
    <td>Generated on device, stored in the Keychain behind biometrics, never transmitted.</td></tr>
<tr><td class="no">✗ your notification content</td>
    <td>The push bridge sees a topic hash and sends a generic "New message". It could not
        decrypt one if it wanted to.</td></tr>
<tr><td class="yes">✓ your public key and username</td>
    <td>The server <b>is</b> the directory — that is how anyone finds you. Lookup is exact-match
        only: there is nothing to browse and nothing to enumerate.</td></tr>
<tr><td class="yes">✓ your friend graph</td>
    <td>Stored as rows naming both client ids. An id is <code>sha256</code> of a public key, which
        makes it a commitment, not an anonymisation — anyone holding the key can derive it. We are
        not going to dress this up: those rows <b>are</b> the relationship, and a server compromise
        exposes them.</td></tr>
<tr><td class="yes">✓ topic names, sizes and timing</td>
    <td>Cloudflare terminates TLS and sees the same. End-to-end encrypted is not the same
        claim as unobserved, and we are not making the second one.</td></tr>
</tbody></table>`);

const LIMITS = `
<div class="card warn"><span class="lbl">first contact is trust-on-first-use</span>
  <p class="ui">The first time you add someone, their key is accepted as given. Safety numbers
  and a QR code let you compare keys out of band, and a key change raises a banner — but
  verification is optional and most people skip it. Substitution at first contact is
  <b>visible to someone who checks</b>, not <b>prevented</b>. We do not claim MITM protection.</p></div>

<div class="card warn"><span class="lbl">endpoint compromise beats all of this</span>
  <p class="ui">If someone has your unlocked device, the cryptography is beside the point.
  The project's own threat model reaches the same conclusion: server compromise costs
  metadata and ciphertext, and everything that is left sits on the endpoint and on first
  contact.</p></div>

<div class="card warn"><span class="lbl">no third-party audit</span>
  <p class="ui">There have been standing self-assessments against OWASP ASVS and MASVS. There
  is now some dynamic testing too: the
  two parsers that read the network before anything authenticates it are fuzzed against each
  other, and one command runs a whole conversation — real HQC, real ratchet, both wire
  versions — through the compiled Swift. That has found real bugs, and the wire section above
  names four of them. But it is our own testing. <strong>No penetration test, no load test,
  no external review, no third-party audit.</strong> Treat "audited" as a word we have not
  earned.</p>
  <p class="ui note">the Apple fuzzer's default driver is also coverage-blind — Apple's
  toolchain ships no libFuzzer runtime — so out of the box it is a random walk around a seed
  corpus rather than a guided search. that is a real limit and it is written down.</p></div>

<div class="card warn"><span class="lbl">no recovery, and that cuts both ways</span>
  <p class="ui">Your identity is a keypair held on one device behind biometrics. There is no
  password reset, because there is no password, and no key escrow to reset it from. Lose the
  device and the identity and its history are gone. Re-enrolling Face ID currently destroys
  them too — a known issue, tracked as a release gate, not yet fixed.</p></div>

<div class="card warn"><span class="lbl">published source is not a verified binary</span>
  <p class="ui">The app's source is published; the build on your phone came from the App
  Store. <b>Nothing links the two.</b> The build is not reproducible, so reading the code
  tells you what this project wrote, not what was shipped to you — the same gap every
  store-distributed app has, named here rather than left for you to notice. If it matters,
  build it from the repository and run that instead.</p></div>

<div class="card warn"><span class="lbl">TLS pinning is not on</span>
  <p class="ui">The app carries pinning code, but ships with no pins configured, so today it
  uses ordinary system trust. Do not count on pinning until this line changes.</p></div>`;

/* ── the pages ───────────────────────────────────────────────────────────── */

const homePage = shell(
  {
    title: "post-quantum encrypted messenger for iPhone",
    path: "",
    desc:
      "hqChat is an end-to-end encrypted messenger for iPhone and iPad, free on the App " +
      "Store. Post-quantum HQC-256 key agreement, AES-256-GCM, and published source.",
  },
  `
<section class="hero">
  ${MARK}
  ${WORDMARK}
  <p class="tag">private, post-quantum messaging</p>
  <p class="lede">1:1 messages between two devices, with the key agreement done by a
  post-quantum KEM instead of an elliptic curve. The server routes ciphertext it cannot
  read — and <strong>both halves are published</strong>, the app that does the encrypting
  and the server that does not, so you can read the code that makes the claim.</p>
  <p class="cta"><a class="btn" href="${DOWNLOAD_URL}">${APP_STORE_NAME} on the app store</a>
  <span class="note sub">free, for iPhone and iPad, iOS ${APP_MIN_IOS} or later. no account to
  make, nothing to buy in it.</span></p>
  ${DONATE_FORM}
  ${donateNote()}
</section>

<hr>

${sec(
  "whoami",
  `
  <div class="grid">
    <div>
      <p>hqchat is a messenger for <strong>iOS and macOS</strong>. Your identity is a keypair,
      not an account: no phone number, no email address, no password — and correspondingly no
      way for anyone, us included, to reset it or hand it to somebody who asks nicely.</p>
      <p>You can hold several identities on one device, fully separate: different keys,
      different contacts, different history, no thread between them.</p>
    </div>
    <div class="card brk"><i></i>
      <span class="lbl">v0 — what actually works today</span>
      <ul class="bare">
        <li>1:1 text messages</li>
        <li>presence, and the friend graph</li>
        <li>invite by exact username</li>
        <li>safety numbers + QR key verification</li>
        <li>push notifications, with no message content in them</li>
        <li>@helper, with AI replies if you turn them on</li>
      </ul>
      <p class="note">no groups. no calls, photos or voice notes — those were cut when the
      transport moved to MQTT. no read receipts or typing indicators, deliberately. there is
      no web client and there is not going to be one.</p>
    </div>
  </div>`,
)}

${sec(
  "cat helper.txt <em># the account you start with, and its opt-in AI</em>",
  `
  <div class="grid">
    <div>
      <p>Every new account starts with one contact, <strong>@helper</strong>, so the first
      conversation isn't an empty screen. It is an ordinary account on the same protocol, run
      by us: like any contact, it decrypts what you send it.</p>
      <p>It can answer with AI — <strong>Claude Haiku, by Anthropic</strong> — but only after you
      send it <code>/ai on</code>. From then on, the text you send in that one chat goes to
      Anthropic to write the reply. Your other chats, your contacts and your keys never reach
      the helper, so they never reach Anthropic either.</p>
    </div>
    <div class="card brk"><i></i>
      <span class="lbl">what /ai on means</span>
      <ul class="bare">
        <li>off until you send <code>/ai on</code>; <code>/ai off</code> stops it</li>
        <li>only the text of your chat with @helper is sent</li>
        <li>the last few messages are kept in memory, never on disk; <code>/forget</code> clears them</li>
        <li>a few dozen replies a day each, so nobody can run up the bill</li>
        <li>AI replies can be wrong</li>
      </ul>
      <p class="note">the app marks @helper with an AI badge, from ids pinned in the app rather
      than told by the server. on a server you run yourself, the AI is off unless you give the
      bot your own key.</p>
    </div>
  </div>`,
)}

${sec(
  "cat crypto/primitives",
  `
  <p>Four primitives, named exactly, so you can go and check the claims rather than take
  them.</p>
  ${PRIMITIVES_TABLE}
  ${NOT_HYBRID}`,
)}

${sec(
  "cat crypto/handshake.txt <em># how two devices agree on a key</em>",
  `
  <p>The initiator encapsulates to three of the responder's keys at once — the pinned
  identity key, a medium-term prekey, and a single-use one-time prekey when one is left —
  and mixes all three secrets into the first root. The identity encapsulation is what proves
  the <em>responder</em>, because only the holder of that key can decapsulate; the prekeys are
  what buy forward secrecy. Following PQXDH, that combination is why the prekeys need no
  signature, which matters because HQC is a KEM and cannot produce one.</p>
  <p>It also means the first flight proves nothing about who <em>sent</em> it — every value in
  it is public. So the responder does not accept an <code>init</code> on its word: it holds the
  frame and encapsulates a challenge back to the identity key the frame claims, and the
  initiator has 60 seconds to answer with an HKDF proof over that secret. Only then is the
  session real.</p>
  ${scroll(HANDSHAKE)}
  <p class="note">this is encapsulation, not a diffie–hellman: there is no shared group
  element, and possession of the private key is the whole proof. the responder can still be
  offline while the first message is sent — it waits in their inbox topic — but the round
  trip is now the price of knowing who sent it.</p>`,
)}

${sec(
  "cat crypto/ratchet.txt <em># and how that key stops being the same key</em>",
  `
  <p>A single long-lived key would mean one compromise decrypts everything, past and future.
  So the channel key is only a starting point: a per-message chain gives
  <strong>forward secrecy</strong>, and a periodic fresh HQC exchange gives
  <strong>post-compromise security</strong> — the property that lets a conversation recover
  after a device has been breached.</p>
  ${scroll(RATCHET)}
  <p class="note">we call this a ratchet with periodic post-quantum re-keying, not "the
  double ratchet" — there is no per-message asymmetric step, and borrowing signal's name for
  a different construction would be the kind of thing this page exists to avoid.</p>`,
)}

${sec(
  "cat server/what-it-sees",
  `
  <div class="grid flip">
    <div class="card acc">
      <p class="ui" style="margin:0">The server is a relay and an access-control point. It is
      not a store. The honest summary is the one the repository uses on itself: <strong>it fans
      out ciphertext it cannot read</strong>.</p>
    </div>
    <div>
      <p>Which is a real property, and a narrower one than "private". Here is the whole list,
      including the parts that are not flattering — because a server that knows your username,
      your contacts and your timing has no business being described with words that imply it
      knows nothing about you.</p>
    </div>
  </div>
  ${SERVER_TABLE}
  ${scroll(TOPOLOGY)}`,
)}

${sec(
  "git clone hqchat",
  `
  <div class="grid">
    <div>
      <p>Every claim above is a claim about software you cannot see running. So both halves
      are <strong>published</strong>: the app, and the server it talks to.</p>
      <p>The app is the half that decides whether any of this is true. Every key this page
      describes is made, held and used on the device — the server never has one — so "end-to-end
      encrypted" is a statement about the Swift, not about the backend. That Swift is now
      there to read: the HQC binding, the ratchet, the keychain handling, the wire codec, and
      the tests that hold them to the same vectors the server is held to.</p>
      <p>The server is the half you do not have to run. Bring up your own: admission can be
      <code>open</code> or a private allowlist, and pointing a build at a different server is
      one file's worth of change. That is the actual answer to "why should I believe you" —
      not a promise, an exit.</p>
      <p><a href="${CLIENT_REPO}">${CLIENT_REPO}</a><br>
      <a href="${SERVER_REPO}">${SERVER_REPO}</a> · AGPL-3.0</p>
    </div>
    <div class="card brk"><i></i>
      <span class="lbl">what is published</span>
      <ul class="bare">
        <li>the iOS and macOS app, one Xcode project</li>
        <li>the HQC wrapper, the ratchet, the wire codec</li>
        <li>auth, app-api, push-bridge, broker-watch</li>
        <li>the postgres schema and its migrations</li>
        <li>both test suites, and the vectors they share</li>
      </ul>
      <p class="note">and what is not: the deployment — compose, nginx, terraform, the hosts —
      and the open audit findings. a list of unfixed weaknesses beside the code that has them
      helps the wrong reader first. what is in these repositories is the code that runs.</p>
    </div>
  </div>`,
)}

${sec(
  "cat threat-model/limits <em># the section that makes the rest worth reading</em>",
  `
  <p>Anything claiming to protect you should tell you where it stops. These are taken from
  the project's own threat model and its open findings. Those are tracked privately — a list
  of unfixed weaknesses published beside the code that has them helps the wrong reader first —
  so what follows is the summary, written to be the honest version rather than the
  flattering one.</p>
  ${LIMITS}`,
)}

<hr>

${sec(
  "./support",
  `
  <div class="grid">
    <div>
      <p>The whole app is free. Every feature, for everyone, with no account tier and nothing
      to buy anywhere — <strong>a donation unlocks nothing</strong>, because there is nothing
      left locked. What it pays for is the bill below.</p>
      ${DONATE_FORM}
      ${donateNote()}
      <p class="note">the buttons post straight to /donate/checkout on this host, which
      creates a stripe checkout session and sends you there. no account, no form, nothing to
      fill in here at all.</p>
      <p class="note"><a href="/donate">what this is and what it costs</a> ·
      <a href="/supporters">supporters</a></p>
    </div>
    <div class="card brk"><i></i>
      <span class="lbl">what it costs to run</span>
      <table class="costs">
        ${COSTS.map(([what, amount]) => `<tr><td>${what}</td><td>${amount}</td></tr>`).join("")}
      </table>
      <p class="note">${COSTS_TOTAL}, and roughly fixed — more users cost capacity, not money,
      which is why the product is free rather than metered. to stop a recurring donation, use
      the billing-portal link in stripe's own emails: this site has no account area, and
      deliberately no page that will act on a stranger who knows your public key.</p>
    </div>
  </div>
  ${downloadBlock()}`,
)}
`,
);

const AUTH_FLOW = `<pre>  app                                                         auth service
   │  POST /auth/init  { pk }                                      │
   │ ─────────────────────────────────────────────────────────────▶│
   │                                    <b>(ct, ss) = HQC.encap(pk)</b>   │
   │                                    stores <b>HKDF(ss,"auth")</b>     │
   │  { ct }                            <s>60s ttl, single use</s>       │
   │ ◀─────────────────────────────────────────────────────────────│
   │                                                               │
   │  <b>ss = HQC.decap(sk, ct)</b>                                       │
   │  POST /auth/verify  { <b>HKDF(ss,"auth")</b>, signing key }        │
   │ ─────────────────────────────────────────────────────────────▶│
   │                                    constant-time compare,     │
   │                                    consume the challenge,     │
   │  { session token, key id }         token stored as <b>sha256</b>     │
   │ ◀─────────────────────────────────────────────────────────────│

  a password would be a shared secret the server has to hold. this is a proof of
  possession instead: the client never returns ss or any decrypted bytes, only a
  derived value, so there is nothing here that works as a decryption oracle.</pre>`;

const cryptoPage = shell(
  {
    title: "the protocol",
    path: "crypto",
    desc:
      "How hqchat encrypts a message: HQC-256 encapsulation to an identity key and two " +
      "prekeys, a challenge-response first contact, and a ratchet that re-keys as it goes.",
  },
  `
${sec(
  "cat crypto/README <em># the long version</em>",
  `
  <h1>how hqchat encrypts a message</h1>
  <p class="lede ui">The short version is on <a href="/">the front page</a>. This is the same
  thing without the shortening — including the parts that are unresolved.</p>`,
)}

<hr>

${sec(
  "cat crypto/primitives",
  `
  <h2>what it is built from</h2>
  ${PRIMITIVES_TABLE}
  <h3>where HQC comes from</h3>
  <p>The implementation is the official reference implementation, pinned to a specific
  upstream commit and compiled into the app. It is deliberately held one commit behind
  upstream: the newer commit changes the bytes it produces, which would break interoperability
  between clients mid-conversation. A CI job watches upstream so that drift is a decision
  rather than a surprise.</p>
  <p>Key generation is deterministic from a 32-byte identity seed, which keeps the public key
  byte-stable across protocol migrations — that is what lets safety numbers and the friend
  graph survive a change to everything around them.</p>
  <p class="note">the compiled HQC binaries are committed to the repository and are not
  reproducibly built, so the link from source to artifact is trust rather than verification.
  it is written down in the threat model, and it is worth knowing. the wrapper around them is
  readable in the <a href="${CLIENT_REPO}">app source</a>.</p>
  ${NOT_HYBRID}`,
)}

${sec(
  "cat crypto/auth.txt <em># proving who you are, without a password</em>",
  `
  <p>There are two handshakes in the system and they are easy to confuse. This is the first:
  a client proving to the server that it holds the private key for a public key. It is a KEM
  challenge–response.</p>
  ${scroll(AUTH_FLOW)}
  <p>Every MQTT connection afterwards is authorised by a fresh, single-use proof signed with
  an Ed25519 key that exists only in the app's memory; the server keeps its public half for
  twelve hours. A captured connection packet cannot be replayed.</p>`,
)}

${sec(
  "cat crypto/handshake.txt <em># two devices agreeing on a key</em>",
  `
  <p>The second handshake, and the one that matters for confidentiality. The server is not a
  participant in it.</p>
  ${scroll(HANDSHAKE)}
  <h3>proving who started it</h3>
  <p>The three encapsulations above are all to the <em>responder's</em> keys, so what they
  demonstrate is that the responder holds its identity secret. Nothing in the frame ever
  demonstrated the reverse — an <code>init</code> is derived entirely from published values:
  a prekey bundle anyone may claim, and a <code>senderPk</code> anyone can fetch. Reproduced
  against this code, that let any accepted friend of A open a session with A while claiming
  to be a third party B, using only B's public key — and A's real conversation with B was
  dead from then on, because B's genuine <code>init</code> arrived afterwards and was refused
  as a replay.</p>
  <p>A KEM cannot fix that in one flight: encapsulation demonstrates the <em>recipient's</em>
  secret, never the sender's. X3DH gets it from a Diffie–Hellman that needs the initiator's
  key, and PQXDH keeps those DHs for exactly this reason. This project is HQC research, so it
  pays a round trip rather than adding a second primitive. The responder holds the
  <code>init</code>, encapsulates a challenge to the identity key the frame names — safe
  because the decoder has already refused any <code>init</code> whose <code>senderPk</code>
  does not hash to its <code>sender</code>, so it <em>is</em> that peer's real key — and waits
  up to 60 seconds for:</p>
  ${scroll(`<pre>  <b>info</b>  = "hqchat/handshake/v2" ‖ nonce(32) ‖ challenger(32) ‖ prover(32) ‖ transcript(32)
  <b>proof</b> = HKDF-SHA256(ikm = ss, salt = "salt", info, 32)</pre>`)}
  <p>Every component is fixed-width, so there is nothing to delimit and no encoding for a
  Swift client and a TypeScript bot to disagree about. The nonce is freshness; binding both
  ids in a fixed order means a proof made for one pair cannot be presented to another, or
  replayed back at its own author. The <code>transcript</code> is a SHA-256 over the init
  itself — both ids and every ciphertext in it — which each side computes on its own and
  never sends. It binds the proof to <em>one</em> init: in v1 it was missing, so a forged init
  naming the initiator was released by the proof the initiator made for its real one. The prover answers only for a handshake it started, so
  this is not a standing decryption oracle for anyone who can reach the topic.</p>
  <p class="note">what it does not stop is a relay — someone who can both see the challenge
  and reach the real B could forward it. what stops that here is the transport: the exchange
  runs on <code>hs/{handshake_id}</code>, a random id only the two members are handed, on a
  broker that refuses wildcard subscriptions. a malicious server still can, and is outside
  what any of this defends: it mints the ids.</p>
  <h3>keeping it live</h3>
  <p>Re-establishing a channel is where this kind of protocol usually goes wrong in
  production, and it did here first. The rules that came out of that: both sides answer an
  <em>offer</em> and nobody answers an <em>answer</em>, or two devices ping-pong forever; each
  side caches its own ciphertext and re-sends that same one rather than generating a fresh
  one; and re-offers back off, because answering one costs the person at the other end a
  Face ID prompt.</p>`,
)}

${sec(
  "cat crypto/ratchet.txt",
  `
  ${scroll(RATCHET)}
  <h3>messages that arrive late, or out of order</h3>
  <p>The receiver ratchets forward to the message it was handed and caches every key it
  skipped past, so a message that arrives after the ones behind it still opens. That cache is
  bounded — a few thousand keys — because an unbounded one is a memory-exhaustion attack
  wearing a feature's clothes. One previous epoch is kept receive-only as a grace window
  while a re-key settles.</p>
  <h3>the first chain, stated plainly</h3>
  <p>A conversation opens on the chain the initiator advertised in its <code>init</code>, and
  the root does not turn until the responder's first reply — that reply always steps. So the
  initiator's opening messages, however many it sends before an answer, sit on one chain.
  They have forward secrecy, because the message chain is one-way from the first message;
  what they do not have is <strong>post-compromise security</strong>, which cannot exist
  before the peer has contributed anything. A monologue nobody replies to never heals.</p>
  <h3>the tag decides, and nothing before it</h3>
  <p>HQC uses <strong>implicit rejection</strong>: decapsulating a forged or corrupt
  ciphertext returns a pseudo-random secret rather than an error. So a fabricated step — a
  random ratchet key and 14421 random bytes — reaches the root derivation and <em>succeeds</em>.
  While the receive path committed before checking the AEAD tag, that one frame replaced the
  root, adopted the sender's ratchet key and reset the receive chain; the tag then failed, and
  the session was saved anyway. The two sides could never converge again, and no re-handshake
  could rescue it, because a fresh <code>init</code> is refused as a replay by anyone who has
  already heard from you. Any accepted friend could send that frame.</p>
  <p>The KEM cannot tell you a step was forged. The tag can. So nothing is written to the
  session — not the root, not the adopted key, not even the removal of a cached skipped key —
  until the AEAD has opened the payload, and the decrypt is passed <em>into</em> the ratchet
  as the verifier rather than handed back to four call sites that each have to remember.</p>`,
)}

${sec(
  "cat crypto/wire.txt <em># the bytes two clients actually exchange</em>",
  `
  <p>The ratchet decides what a key is. The wire format decides what the two implementations
  agree they are looking at — and for a protocol written twice, once in Swift and once in
  TypeScript, that second question is where the bugs live.</p>
  <p><strong>There used to be two formats. There is one.</strong> v2 was JSON carrying
  base64, and it is deleted — nothing reads it, and a v2 frame is now refused like any other
  non-frame. The rest of this section is why, because the reasons are the reasons the
  current format looks the way it does.</p>
  <p>Base64 cost the 33% you would expect, which landed hardest on the frames that already
  hurt: roughly 24 kB of every 82 kB <code>init</code> was encoding rather than protocol. But
  size was never the strongest argument. The AAD has to agree byte-for-byte between the two
  implementations, and in v2 it was a <em>second</em> construction — a netstring of a fixed
  field order, hand-written on both sides, beside a JSON encoding produced by two different
  libraries.</p>
  <p>Running the two parsers against each other found four ways that drifts, none of which
  any test had caught:</p>
  <ul>
    <li><strong>Duplicate keys.</strong> RFC 8259 leaves the winner undefined. JavaScript's
    <code>JSON.parse</code> keeps the last value, Swift's <code>JSONDecoder</code> keeps the
    first — so one frame naming <code>sender</code> twice is two different frames to two
    peers.</li>
    <li><strong>Lone surrogates.</strong> <code>"&#92;ud83d"</code> with no pair is accepted by
    <code>JSON.parse</code> and produces a string no UTF-8 encoder can represent; the AAD is
    then built over substituted bytes rather than the ones on the wire. <code>JSONDecoder</code>
    refuses the document outright.</li>
    <li><strong>Graphemes counted where bytes were meant.</strong> Every length in the
    canonical header is now measured in UTF-8 bytes on both sides.</li>
    <li><strong>Wrong-typed optionals.</strong> A <code>msg</code> carrying
    <code>"ctOt": {}</code> passed validation and had the object stringified into the AAD.
    Every optional is type-checked now, whatever the frame kind.</li>
  </ul>
  <p>Both classes that survive on text are unreachable now — there is no text on the wire at
  all. And <code>n</code>, <code>pn</code> and <code>otId</code> are unsigned 32-bit, because
  the binary header has four bytes for them; v2 admitted any safe integer, so there were v2
  frames with no v3 expression, which made the version a lie rather than a spelling.</p>
  <p><strong>The second construction is gone entirely.</strong> The canonical header
  <em>is</em> the frame's own prefix, so the AAD is a byte range of the thing that arrived —
  there is nothing to keep in step. Two fields are bound that were not: the version, so a
  client cannot be flipped between formats without breaking the tag, and <code>to</code>, the
  recipient's client id. A v2 frame said who it was from and never who it was for, which is
  why a receiver had to fall back on checking the topic it arrived on; that check is
  cryptographic now instead of transport-level. It is kept anyway, as defence in depth — it
  is cheap, and it caught a real bug.</p>
  ${scroll(WIRE)}
  <h3>how a wire version actually changed</h3>
  <p>Worth keeping, because it is the shape of the job rather than a detail of one format.
  <strong>Every build read both versions, always — that was never a setting.</strong> Which
  one a build <em>emitted</em> was: a compile-time default, overridable per build on Apple and
  per deployment on the server. The asymmetry was the whole rollout plan. A peer on an older
  build drops a frame it cannot read <em>silently</em>, so acceptance had to ship a full
  release before emission moved anywhere.</p>
  <p>And the recipient binding bought nothing while v2 was still accepted — an attacker who
  wanted to avoid it simply sent v2, and both receivers took it. The protection arrived when
  v2 <em>acceptance</em> was dropped, which is a decision that needs evidence rather than a
  memory: each process counted the well-formed frames it had read of each version, and zero
  v2 was the condition. Without a number, "confirm there are no stragglers" is a feeling, and
  a transitional state with no trigger is how a transition becomes permanent.</p>
  <p>Both halves are done, so both flags and the tally are deleted. Dropping emission was
  recoverable; dropping acceptance was not, and that is why it was a separate step with a
  reading behind it.</p>
  <p class="note">the flip is announced rather than enforced: the server can push an advisory
  note to every client, and it blocks nothing. a hard gate during a maintenance window is the
  wrong instinct for a security reason — the window is exactly when a client most needs to
  reach the server, to receive the build that closes whatever the window is for.</p>`,
)}

${sec(
  "cat crypto/at-rest.txt <em># the copy on your device</em>",
  `
  <p>Encrypting the wire is the easy half. The message history sitting on the device is
  encrypted too: each message body gets a fresh random AES key, and that key is wrapped to a
  <strong>P-256 key held in the Secure Enclave</strong>, created so that it can be used but
  never extracted.</p>
  <p>The asymmetry is deliberate. Sealing needs no user present, so a message that arrives
  while your phone is in your pocket can still be written down. <em>Reading</em> history
  needs biometrics. There is no symmetric fallback: a body that cannot be sealed is not
  stored at all.</p>
  <p>Your identity key sits in the Keychain bound to the current biometric enrolment, and is
  read only for sign-in and handshakes — never to read a message. Reads are batched behind a
  short unlock window that does not slide, so signing in costs one Face ID rather than one
  per contact, and a remote peer cannot hold the key resident by sending frames.</p>
  <p>Deleting a profile deletes its keypair, which makes that profile's stored messages
  permanently unopenable. That is the intended behaviour, not a side effect.</p>`,
)}

${sec(
  "cat server/what-it-sees",
  `
  ${SERVER_TABLE}
  ${scroll(TOPOLOGY)}
  <p>Conversation topics — and the handshake topic beside each one — are random ids the
  server mints when a friendship is made: 64 hex characters from two random UUIDs, so 244
  random bits. Nothing about them follows from the two client ids or keys, and the server
  hands them only to the friendship's two members. They are also the access control. The
  broker's ACL is a static file, not a lookup: any signed-in client may publish to and read
  from <code>cv/</code> and <code>hs/</code> topics, by exact name only, since wildcard
  filters are refused. Knowing a conversation's id is therefore the permission to
  read its ciphertext and to write into it, which is why an id is never logged, never
  derived, and never shown to anyone but its two members — and why the threat model treats
  the ids as secrets.</p>`,
)}

${sec("cat threat-model/limits", LIMITS)}

${sec(
  "./support",
  `${DONATE_FORM}${donateNote()}
  <p class="note">or read the whole thing first —
  <a href="${CLIENT_REPO}">the app</a> and <a href="${SERVER_REPO}">the server</a>.</p>`,
)}
`,
);

/* ── legal pages ─────────────────────────────────────────────────────────────
 * Ported from the previous apps/web Worker, with three statements corrected
 * because they had stopped being true and this is a document the App Store
 * requires to be accurate:
 *   - it promised end-to-end encrypted photos and voice/video calls; those were
 *     cut from v0 when the transport moved to MQTT.
 *   - it described a 7-day server-side queue for undelivered messages; there is
 *     no such queue any more, only the broker's own persistent session.
 *   - it described iOS in-app subscriptions billed through Apple; StoreKit was
 *     removed from the app entirely and nothing is sold through Apple.
 *   - it described a subscription that unlocked contacts, an email hash held to
 *     identify subscribers, and retention "for billing and tax purposes". The
 *     paywall was replaced by donations: nothing is sold at all now, and no
 *     email address — hashed or otherwise — reaches the server.
 * The product name is still in flux (hqchat / HQChat); until that is settled
 * these pages bridge the two on first mention rather than silently renaming a
 * product inside its own terms of service.
 */

const privacyPage = shell(
  {
    title: "privacy policy",
    path: "privacy",
    desc:
      "What the hqchat server holds and what it does not: no message content except a " +
      "report you send, no phone number, no email address, no address book.",
  },
  `<div class="doc">
  <h1>privacy policy</h1>
  <p class="updated">last updated: ${LAST_UPDATED}</p>

  <p>hqchat (listed on the App Store as ${APP_STORE_NAME}) is an end-to-end encrypted messenger. This
  policy describes what the app and its servers do and do not collect. The guiding principle:
  it is built so that we <strong>cannot</strong> read your messages.</p>

  <h2>what we cannot see</h2>
  <p>Your messages are end-to-end encrypted on your device using an HQC-256 post-quantum key
  exchange and AES-256-GCM. The keys are generated on your device and never leave it. Our
  servers relay already-encrypted data between devices and are technically unable to decrypt
  it.</p>

  <h2>what we store</h2>
  <ul>
    <li><strong>Your username</strong> — the handle you choose, so others can find you.</li>
    <li><strong>Your public key</strong> — needed to route encrypted messages to you.</li>
    <li><strong>Friend connections</strong> — stored so we can deliver messages and presence.</li>
    <li><strong>Undelivered messages</strong> — if you are offline, the encrypted message is
        held in your session on our message broker, in memory, for when your device
        reconnects. We cannot read it, and it is not written to any database. The session
        holds at most 1000 messages and ends after two hours offline: past either limit,
        undelivered messages are dropped, oldest first, and never arrive.</li>
    <li><strong>Push token</strong> — if you enable notifications, so we can wake your device.
        Notification payloads contain no message content.</li>
    <li><strong>A message you report, if you report one</strong> — reporting uploads your
        own copy of that message so a human can read it (App Store Guideline 1.2 requires a
        way to report content, and a report with nothing to look at is a complaint). A
        report also records who filed it, who it is about, and which conversation it came
        from. It is <a href="/eula">deleted after 90 days</a>. We cannot verify an excerpt —
        it is the reporter's own copy and anyone could type anything — so it is read as what
        somebody handed in, not as proof of what was said.</li>
    <li><strong>Who you have blocked</strong> — a row naming the two accounts, so a block
        holds across your devices and cannot be walked around by adding you again. Deleted
        with your account.</li>
    <li><strong>A supporter name, if you type one</strong> — donations are optional and
        processed by Stripe. If you choose to put a name on the
        <a href="/supporters">supporters</a> page, that name is stored on its own: no email,
        no hash of one, no customer id, no amount, and nothing linking it to any account.
        A donation and an identity cannot be connected from our database by anyone,
        including us. If you type nothing, nothing is stored at all.</li>
  </ul>

  <h2>what we do not collect</h2>
  <ul>
    <li>No message content — we cannot decrypt it. Two exceptions, both your choice: a
        message <em>you</em> choose to report (see "what we store" above and the
        <a href="/eula">end-user licence agreement</a>), and what you write to
        <strong>@helper</strong>, an account we run (see "the helper and its AI replies"
        below). We would rather carry the asterisk than write a sentence that stops being
        true the first time somebody reports harassment.</li>
    <li>No address-book or contact uploads.</li>
    <li>No advertising identifiers, ad networks or third-party ad trackers.</li>
    <li>No behavioural or advertising analytics, and no profiling for marketing. (We do
        collect crash and hang reports — see below.)</li>
    <li>No selling or sharing of personal data, ever.</li>
  </ul>

  <h2>crash reports and diagnostics</h2>
  <p>We use <strong>Sentry</strong> (Functional Software, Inc.) for crash reporting. The app
  sends a report only when it crashes, hangs for two seconds or more, or is stopped by the
  system for using too much memory. A report may contain the app and OS version, device
  model, language and region; the crash or hang itself, including stack traces; and up to
  50 of the app's events before it (memory warnings, which screen was open), with
  usernames, ids and key-shaped strings removed on the device. It contains no performance tracing, no record of network requests, no screenshots
  or screen recordings, and no user or installation identifier. On the server only, a
  report may include your username or public key when that is needed to reproduce a
  routing error.</p>
  <p>Your encrypted messages are <strong>never</strong> included and remain unreadable to us
  and to Sentry. This data is used solely to diagnose stability problems — never for
  advertising, never to build a profile — and is not sold or shared. Sentry processes it as
  our data processor under its own privacy terms.</p>

  <h2>your private keys</h2>
  <p>Your identity's private key is stored in the device Keychain and Secure Enclave, protected
  by your device biometrics. It is never transmitted to us. If you delete the app or reset your
  data, the identity — and your ability to decrypt past messages on that device — is
  permanently lost. This is by design, and there is no recovery path.</p>

  <h2>deleting your account</h2>
  <p>You can permanently delete your account at any time from the app: <em>settings → delete
  account</em>. This removes your username, public key, friend connections, push token,
  queued messages and your blocks from our servers, and erases the data stored on your
  device. It cannot be undone.</p>
  <p><strong>One thing does not go, and we would rather explain it than leave it out.</strong>
  A report somebody filed <em>about</em> you survives your account deletion, until its own
  90 days are up. If it did not, deleting an account would be a way to erase the complaints
  against it — delete, re-register, start again — and a reporting mechanism that works like
  that is not one. What deletion does do to reports is remove <em>your</em> half: every
  report you filed stops naming you as the person who filed it. The message excerpt in it
  was one you chose to hand in about somebody else, so it stands, and it expires on its own
  clock either way.</p>

  <h2>data retention</h2>
  <p>Undelivered messages live only until delivery. Account data persists until you delete your
  account. <strong>Reports are deleted 90 days after they are filed</strong> — not when the
  account they name is deleted, and not when the reporter's is; the clock is the report's
  own and nothing lengthens or shortens it. Donation records are held by Stripe, not by us, and are retained by Stripe as
  required for payment and tax purposes.</p>

  <h2>children</h2>
  <p>hqchat is not directed to children under 13 (or the minimum age in your country) and we do
  not knowingly collect their data.</p>

  <h2>the helper and its AI replies</h2>
  <p>Every new account starts with one contact, <strong>@helper</strong>, an account we run.
  Like any contact, it decrypts the messages you send it, and only those.</p>
  <p>It can answer with AI, but only if you send it <code>/ai on</code>. From then on, the text
  you send in your chat with @helper is sent to <strong>Anthropic</strong> (Claude Haiku) to
  write the reply. Nothing else is: not your other chats, your contacts, your keys, or your
  username. The helper keeps the last few messages of that chat in memory to follow the
  conversation; they are never written to disk, <code>/forget</code> clears them, and
  <code>/ai off</code> stops AI replies and clears them too. The helper stores only which
  accounts turned AI on and how many replies each had today. Anthropic processes the text
  under its own commercial terms and privacy policy. AI replies can be wrong.</p>

  <h2>third parties</h2>
  <p>We use Apple (push notifications), Stripe (donations), Cloudflare (network and edge),
  Sentry (crash reporting) and, only if you turn on the helper's AI replies, Anthropic (AI
  replies). Each processes only the limited data described above under their own privacy
  terms.</p>

  <h2>changes</h2>
  <p>We may update this policy; material changes will be reflected by the date above.</p>

  <h2>contact</h2>
  <p>Questions about privacy: <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a>.</p>
</div>`,
);

const termsPage = shell(
  {
    title: "terms of service",
    path: "terms",
    desc:
      "The terms for using hqChat, the post-quantum encrypted messenger for iPhone and " +
      "iPad. Nothing is sold in the app; donations unlock no feature.",
  },
  `<div class="doc">
  <h1>terms of service</h1>
  <p class="updated">last updated: ${LAST_UPDATED}</p>

  <p>By using hqchat (listed on the App Store as ${APP_STORE_NAME}) you agree to these terms.</p>

  <h2>the service</h2>
  <p>hqchat provides end-to-end encrypted 1:1 messaging. You are responsible for your device,
  your identity keys, and the people you communicate with. Because messages are encrypted
  end-to-end and the keys exist only on your device, we cannot recover lost keys or message
  history — for anyone, under any circumstances.</p>

  <h2>reliability and diagnostics</h2>
  <p>To keep the service running and to fix problems, we collect crash and hang reports via
  Sentry, as described in our
  <a href="/privacy">privacy policy</a>. This never includes the content of your messages.</p>

  <h2>acceptable use</h2>
  <p>You agree not to use hqchat to break the law, harass others, distribute malware, or
  infringe others' rights. We may decline service to accounts that abuse the network.</p>
  <p>That clause used to have nothing behind it. It does now: the
  <a href="/eula">end-user licence agreement</a> sets out what is not allowed and what
  happens to accounts that do it, every message in the app can be reported, anyone can be
  blocked, and reports are acted on within 24 hours. Where that page and this one disagree
  about acceptable behaviour, that page governs.</p>

  <h2>donations</h2>
  <p>hqchat is free. Nothing is sold, here or in the app, on any platform: there is no
  subscription, no paid tier and no in-app purchase, and no feature depends on payment.
  Donations are entirely voluntary and are processed by <strong>Stripe</strong>.</p>
  <p>A donation <strong>purchases nothing</strong> — no product, no feature, no service, and
  no promise that any future feature will exist. It creates no entitlement and no refund
  obligation. We are not a registered charity and donations are <strong>not
  tax-deductible</strong>; hqchat is an independent project run by one person, and the money
  goes to that person's hosting bill.</p>
  <p>A recurring donation renews until cancelled. To cancel, use the billing-portal link in
  the emails Stripe sends you. If you would like a donation refunded, write to
  <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a> — we are not obliged to refund one
  and will not pretend otherwise, but we would rather return money than keep it from someone
  who regrets giving it.</p>
  <p>If you give a name at checkout it is published on the
  <a href="/supporters">supporters</a> page. That is the only thing a donation records on
  this server; write to the address above to have a name removed.</p>

  <h2>the helper's AI replies</h2>
  <p>If you turn on AI replies from <strong>@helper</strong> (<code>/ai on</code>), its answers
  are written by an AI model (Claude Haiku, by Anthropic). They can be wrong, they are not
  advice of any kind, and nothing that matters should rest on them. Do not send the helper
  anything you would not want sent to Anthropic; see the <a href="/privacy">privacy
  policy</a>.</p>

  <h2>no warranty</h2>
  <p>hqchat is provided "as is", without warranties of any kind. We do not guarantee
  uninterrupted or error-free service. The security properties described on this site are
  described accurately to the best of our knowledge, including their published limits, but
  they are not a warranty.</p>

  <h2>limitation of liability</h2>
  <p>To the maximum extent permitted by law, we are not liable for indirect or consequential
  damages arising from your use of the service.</p>

  <h2>contact</h2>
  <p><a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a></p>
</div>`,
);

/* ── /eula ──────────────────────────────────────────────────────────────────
 * The end-user licence agreement, as its own page rather than a section of
 * /terms, for one practical reason: App Store Connect takes ONE custom-EULA URL,
 * a reviewer checking Guideline 1.2 opens exactly that URL, and /terms is mostly
 * about donations, refunds and warranty. A reviewer should not have to find the
 * four sentences that matter among them.
 *
 * ⚠️ Guideline 1.2 asks for four things TOGETHER, and each has to be a real
 * mechanism rather than a promise on this page: the agreement (this), a way to
 * report content (in-app, on any message), a way to block a person (in-app, from
 * contacts or from the report sheet), and a contact point that answers
 * (/support). A clause with nothing behind it is what this page replaced.
 *
 * ⚠️ The 24-hour commitment below has a procedure behind it:
 * docs/runbooks/moderation.md. If that stops being true, this sentence has to
 * change on the same day.
 */
const eulaPage = shell(
  {
    title: "end-user licence agreement",
    path: "eula",
    desc:
      "The hqChat licence agreement: the zero-tolerance policy for abusive content, how to " +
      "report a message, how to block a user, and the 24-hour rule.",
  },
  `<div class="doc">
  <h1>end-user licence agreement</h1>
  <p class="updated">last updated: ${LAST_UPDATED}</p>

  <p>This agreement covers your use of hqchat (listed on the App Store as ${APP_STORE_NAME}). You
  accept it in the app, before you create an identity. If you do not accept it, do not use
  the app. It sits alongside our <a href="/terms">terms of service</a> and
  <a href="/privacy">privacy policy</a>; where this page and /terms disagree about acceptable
  behaviour, this page governs.</p>

  <h2>no objectionable content, and no abusive users</h2>
  <p>There is <strong>zero tolerance</strong> for objectionable content or abusive behaviour.
  You agree not to use hqchat to send, request or solicit:</p>
  <ul>
    <li>sexual content involving minors, or any material that sexualises a child — reported
    to the authorities, always, without exception;</li>
    <li>harassment, stalking, threats of violence, or content intended to intimidate or
    humiliate a specific person;</li>
    <li>content that incites violence or hatred against a person or a group;</li>
    <li>spam, scams, phishing, or malware;</li>
    <li>anything that is illegal where you are, or that infringes someone else's rights.</li>
  </ul>
  <p>Accounts that do these things are removed from this server. That is not a warning
  system with steps; a single credible report of the first item ends an account
  immediately.</p>

  <h2>reporting</h2>
  <p>Every message in the app can be reported: press and hold it, choose <em>report</em>,
  say what happened. Reports are reviewed and acted on <strong>within 24 hours</strong>.</p>
  <p>Two things about a report are worth knowing before you send one, and the app says both
  on the screen where you send it:</p>
  <ul>
    <li><strong>It uploads that message's text to this server.</strong> Messages are
    end-to-end encrypted and this server cannot read them — a report is the one path that
    hands one over, and it happens because you chose to, not as a side effect.</li>
    <li><strong>A reported excerpt is not verifiable.</strong> It is the reporter's own copy
    of a message, and this server has no way to tell a genuine one from an invented one. It
    is read as what somebody handed in, not as proof of what was said. We would rather say
    that plainly than imply a check that does not exist.</li>
  </ul>
  <p>Reports are deleted 90 days after they are filed. Deleting your account does not delete
  reports filed <em>about</em> you — otherwise deleting an account would be a way to erase
  the complaints against it — but it does remove your name from reports you filed. See the
  <a href="/privacy">privacy policy</a>.</p>

  <h2>blocking</h2>
  <p>You can block anyone, from their contact row or from the report screen. Blocking ends
  the friendship, revokes their access to your conversation on the server, and cannot be
  walked around by adding you again. Your own copy of the conversation stays on your device,
  read-only, until you delete it. You can unblock later; that does not restore the
  friendship, and neither of you can message the other until one of you asks again.</p>

  <h2>what we can and cannot do about a report</h2>
  <p>We can remove an account from this server, revoke its access to conversations, and
  disconnect it. We cannot read your messages, so we act on what a reporter hands us and on
  what the server itself can see.</p>
  <p>And one honest limit: an identity here is derived from a key your device generates, so
  somebody who is removed can reinstall the app and arrive as a new person with a new
  identity. A ban cannot follow a human being across that on this architecture. What it does
  do is end the account that was reported, break its existing conversations, and require
  anyone who wants to reach you to be added by you again.</p>

  <h2>your account</h2>
  <p>You are responsible for your device and your identity keys. Keys exist only on your
  device and are never sent to us, so a lost key cannot be recovered by anyone, including
  us. You may delete your account from within the app at any time.</p>

  <h2>contact</h2>
  <p>Abuse reports, questions, and anything else: <a href="/support">support</a>, or
  <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a>. A person reads that address.</p>
</div>`,
);

const supportPage = shell(
  {
    title: "support",
    path: "support",
    desc:
      "Help with hqChat: how to reach a person, what happens to your identity if you " +
      "reinstall, how to delete your account, and how to stop a donation.",
  },
  `<div class="doc">
  <h1>support</h1>
  <p class="updated">happy to help.</p>

  <h2>contact</h2>
  <p>Email <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a> and we will get back to you.</p>

  <h2>common questions</h2>
  <p><strong>I reinstalled and lost my account.</strong> Your identity key lives only on your
  device and is not backed up to us, so reinstalling creates a fresh identity. This is
  intentional, and it is not recoverable.</p>
  <p><strong>Do I have to pay for anything?</strong> No. Every feature is free for everyone,
  there is no paid tier, and nothing is sold in the app or on this site. Donations are
  voluntary and unlock nothing.</p>
  <p><strong>How do I stop a recurring donation?</strong> Use the billing-portal link in the
  emails Stripe sends you. There is no account area on this site, deliberately.</p>
  <p><strong>Take my name off the supporters page.</strong> Email us and it goes.</p>
  <p><strong>How do I delete my account?</strong> In the app: <em>settings → delete account</em>.
  This permanently removes your data from our servers and your device.</p>

  <h2>the code</h2>
  <p>Both halves are published, so a question about what the app or the server does with
  something can be answered by reading it rather than by taking our word.</p>
  <p><a href="${CLIENT_REPO}">app source</a> — the iOS and macOS app.<br>
  <a href="${SERVER_REPO}">server source</a> — the services behind it, under AGPL-3.0.</p>
  <p>Security reports go to the address above rather than to a public issue.</p>

  <h2>privacy and terms</h2>
  <p><a href="/privacy">privacy policy</a> · <a href="/terms">terms of service</a></p>
</div>`,
);

/* ── /donate ─────────────────────────────────────────────────────────────────
 * The one page that asks for money, and the only one whose job is to explain
 * the project to somebody deciding whether to fund it.
 *
 * Three sections, in this order and for this reason: what it is (so the ask has
 * a subject), what it costs (so the ask has a number), then the ask. The
 * supporters list is NOT here — it needs the database, so it is served from the
 * origin at /supporters (services/server/src/server/donate.ts).
 */
const donatePage = shell(
  {
    title: "donate",
    path: "donate",
    desc:
      "hqchat is free for everyone and sells nothing. Here is the itemised hosting bill it " +
      "runs on, and an honest list of what a donation does not buy.",
  },
  `
${sec(
  "cat donate/what-this-is",
  `
  <h1>why hqchat asks for donations</h1>
  <p>hqchat is a post-quantum end-to-end encrypted messenger for iOS and macOS. I built it to
  find out whether I could — an entire messaging stack, from the KEM up: the handshake, the
  ratchet, the broker authorization, the infrastructure, the apps. It is a demonstration of
  what I can build, and it is also a real product that really works, which is the only kind of
  demonstration worth anything.</p>

  <div class="grid">
    <div class="card acc"><i></i>
      <span class="lbl">the part most projects would hedge</span>
      <p>This is <strong>not a hybrid</strong>. There is no X25519 underneath and no ML-KEM
      folded in beside it. Nearly every post-quantum deployment ships hybrid so that breaking
      the newer algorithm still leaves a classical one standing. hqchat has no such fallback:
      key agreement is HQC-256 and nothing else.</p>
      <p class="note">If HQC falls, the message layer falls. That is the bet, stated plainly,
      because a project that would not print its own worst sentence has not earned the rest of
      the page.</p>
    </div>
    <div class="card brk"><i></i>
      <span class="lbl">why it needs donations at all</span>
      <p>No ads. No trackers. No analytics. No contact uploads. No investors to eventually
      answer to. There is no data here to sell and no intention of acquiring any — which
      rules out every business model a messenger normally has.</p>
      <p class="note">That is the whole reason for this page. Anything else that could pay
      the bill would compromise the thing being paid for.</p>
    </div>
  </div>`,
)}

<hr>

${sec(
  "cat donate/what-it-costs",
  `
  <p>Roughly fixed, every month, whether five people use it or five thousand. Users cost
  capacity rather than money, which is why the product is free rather than metered — and why
  the honest ask is for help with a standing bill rather than a price per head.</p>
  <table class="costs">
    ${COSTS.map(([what, amount]) => `<tr><td>${what}</td><td>${amount}</td></tr>`).join("")}
  </table>
  <p class="note">${COSTS_TOTAL}. Approximate and rounded: an exact figure here would be stale
  within a billing cycle and worse for being wrong. It does not count the time, which is the
  largest cost and is not for sale.</p>`,
)}

<hr>

${sec(
  "cat donate/the-ask",
  `
  <div class="grid">
    <div>
      ${DONATE_FORM}
      <p class="note">monthly at ${TIERS.map((t) => t.label.replace(" / month", "")).join(", ")},
      or ${ONE_TIME.label}. no account, no form here, nothing to fill in on this site —
      stripe takes it from the button onward.</p>
    </div>
    <div class="card warn"><i></i>
      <span class="lbl">what a donation is not</span>
      <ul>
        <li>it buys <strong>nothing</strong> — every feature is free for everyone, always</li>
        <li>it is <strong>not tax-deductible</strong>; this is not a registered charity</li>
        <li>there is no foundation — it goes to one person's hosting bill</li>
        <li>it promises no future feature, and no particular lifetime for the server</li>
      </ul>
      <p class="note">If you would rather have the software than fund it, take the software:
      the <a href="${CLIENT_REPO}">app</a> and the <a href="${SERVER_REPO}">server</a> are
      both published, and the server is AGPL-3.0. Run your own.</p>
    </div>
  </div>
  <p class="note">stripe asks for an optional name at checkout. leave it blank and nothing at
  all is recorded here; fill it in and it appears on the
  <a href="/supporters">supporters</a> page, stored on its own with nothing to join it to.</p>
  ${downloadBlock()}`,
)}
`,
);

/**
 * ── /robots.txt and /sitemap.xml ────────────────────────────────────────────
 * Served as plain text and XML, never the 404 page, which a crawler would
 * read as markup where a policy should be.
 *
 * ⚠️ robots.txt governs the whole host, not just this Worker, so the disallow
 * list names paths that fall through to the origin (/donate/checkout, the API).
 */
const SITEMAP_PATHS = ["/", "/crypto", "/donate", "/privacy", "/terms", "/eula", "/support"];

const ROBOTS_TXT = `User-agent: *
Allow: /

# Not pages. /donate/checkout is POST-only and mints a Stripe session; the rest
# is the API on the same host. Crawling any of them costs someone money or
# produces a 405, and indexes nothing either way.
Disallow: /donate/checkout
Disallow: /donate/thanks
Disallow: /donate/cancelled
Disallow: /auth/
Disallow: /mqtt
Disallow: /stripe/
Disallow: /health

Sitemap: ${SITE_ORIGIN}/sitemap.xml
`;

/**
 * Deliberately just <loc>s.
 *
 * No <lastmod>, no <changefreq>, no <priority>. The last two are ignored by
 * every major crawler and have been for years. <lastmod> is not ignored, which
 * is exactly why it is absent: this Worker has no per-page modification date to
 * put there, and one constant stamped across seven pages is a claim that every
 * page changed whenever any page did. A sitemap that lies about freshness is
 * discounted wholesale; one that says only "these exist" is believed.
 *
 * /supporters is NOT here, and must not be: it needs the database and is served
 * from the origin, so it is not this Worker's to list.
 */
const SITEMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${SITEMAP_PATHS.map((path) => `  <url><loc>${SITE_ORIGIN}${path}</loc></url>`).join("\n")}
</urlset>
`;

const notFoundPage = shell(
  {
    title: "404",
    path: "404",
    desc: "No such path on hqchat.",
    // No canonical and no og:url: this document has no address of its own, and
    // pointing one at /404 would invite a crawler to index the error page.
    indexable: false,
  },
  `${sec(
    "cat .",
    `
  <h1>404</h1>
  <p>no such path. <a href="/">back to hqchat</a>.</p>`,
  )}`,
);

/* ── router ──────────────────────────────────────────────────────────────── */

/** The security headers every answer carries, whatever its content type. */
const HEADERS = {
  "content-security-policy": CSP,
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
};

function respond(html, status = 200) {
  return new Response(html, {
    status,
    headers: { ...HEADERS, "content-type": "text/html; charset=utf-8" },
  });
}

/**
 * robots.txt and sitemap.xml. Same headers, different content type — and the
 * content type is the entire point: `nosniff` plus `text/html` on a sitemap
 * would get it parsed as markup and thrown away.
 */
function respondText(body, contentType) {
  return new Response(body, {
    status: 200,
    headers: { ...HEADERS, "content-type": `${contentType}; charset=utf-8` },
  });
}

/**
 * The move to hqchat.app, as one answer.
 *
 * 301 rather than 302, because a 302 asks a search engine to keep indexing the
 * OLD url — which is the entire thing this is trying to stop. A permanent
 * redirect is what forwards the links the old host has accumulated.
 *
 * `cache-control` is the other half, and it is there for safety rather than for
 * crawlers. A 301 with no freshness information is cached by browsers until the
 * profile is wiped, so a redirect published by mistake follows a visitor around
 * for months with no way to reach them. An hour bounds that. Search engines key
 * off the STATUS, not the cache header, so this costs nothing in the thing the
 * redirect exists for.
 *
 * The query string is carried across. The site takes no parameters, but
 * campaign tags arrive on links other people wrote, and dropping them turns
 * somebody's attribution into direct traffic.
 */
function redirectToCanonical(url) {
  return new Response(null, {
    status: 301,
    headers: {
      ...HEADERS,
      location: `${SITE_ORIGIN}${url.pathname}${url.search}`,
      "cache-control": "public, max-age=3600",
    },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Before anything is routed: one host serves this site, and the others say
    // so. Safe to do blindly because the edge only ever hands this Worker a
    // marketing path — see the note on CANONICAL_HOST.
    if (url.hostname !== CANONICAL_HOST && !isDevHost(url.hostname)) {
      return redirectToCanonical(url);
    }

    switch (url.pathname) {
      case "/":
        return respond(homePage);
      case "/crypto":
        return respond(cryptoPage);
      case "/donate":
        return respond(donatePage);
      case "/privacy":
        return respond(privacyPage);
      case "/terms":
        return respond(termsPage);
      case "/eula":
        return respond(eulaPage);
      case "/support":
        return respond(supportPage);
      case "/robots.txt":
        return respondText(ROBOTS_TXT, "text/plain");
      case "/sitemap.xml":
        return respondText(SITEMAP_XML, "application/xml");
      default:
        return respond(notFoundPage, 404);
    }
  },
};
