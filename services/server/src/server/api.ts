import type * as http from "node:http";
import { DONATIONS_ENABLED } from "../common/config";
import { core, isPeerId } from "../common/core";
import { logger } from "../common/logger";
import { DB, type PushEnvironment, type PushPlatform, REPORT_CATEGORIES, type ReportCategory } from "./db/api";
import { handleDonate } from "./donate";
import { EMQX } from "./emqx";
import {
  bearer,
  HttpError,
  MAX_BODY_BYTES,
  optionalBase64,
  optionalString,
  readJson,
  requireHex,
  requireString,
  send,
} from "./http";
import { displayNameFromSession, StripeService } from "./stripe";

const HQC_PUBLIC_KEY_BYTES = 7237;
const MAX_ONETIME_PER_UPLOAD = 8;
/** Largest one-time prekey id: the column is a Postgres integer. */
const MAX_PREKEY_ID = 2 ** 31 - 1;
const PREKEY_UPLOADS_PER_DAY = Number(process.env.PREKEY_UPLOADS_PER_DAY || 30);
const PREKEY_CLAIMS_PER_HOUR = Number(process.env.PREKEY_CLAIMS_PER_HOUR || 120);
/** One-time prekeys one friend may take from another per window; later claims get the medium-term key. */
const ONETIME_CLAIMS_PER_PAIR = 1;
const ONETIME_CLAIM_WINDOW_SECONDS = 10 * 60;
const MAX_PEER_IDENTIFIER = 128;
const FRIEND_CAP = Number(process.env.FRIEND_CAP || 150);
const INVITES_PER_DAY = Number(process.env.INVITES_PER_DAY || 20);
const REPORTS_PER_DAY = Number(process.env.REPORTS_PER_DAY || 20);
const MAX_REPORT_NOTE = 2000;
const MAX_REPORT_EXCERPT = 4000;
const MAX_REPORT_FRAME_BYTES = 96 * 1024;
const MAX_REPORT_MESSAGE_ID_BYTES = 128;
const DAY_SECONDS = 24 * 60 * 60;
/** The deployment's helper bot, the only identity allowed a reserved username. */
const BOT_ID = (process.env.BOT_ID || "").toLowerCase() || null;

if ((MAX_ONETIME_PER_UPLOAD + 1) * HQC_PUBLIC_KEY_BYTES * 2 > MAX_BODY_BYTES / 2) {
  throw new Error("a prekey upload can exceed MAX_BODY_BYTES; lower MAX_ONETIME_PER_UPLOAD");
}
if (Math.ceil(MAX_REPORT_FRAME_BYTES / 3) * 4 + MAX_REPORT_NOTE + MAX_REPORT_EXCERPT + 512 > MAX_BODY_BYTES) {
  throw new Error("a report can exceed MAX_BODY_BYTES; lower MAX_REPORT_FRAME_BYTES");
}

type Request = { req: http.IncomingMessage; res: http.ServerResponse; id: string };
type Route = (r: Request) => Promise<void>;

const ok = (res: http.ServerResponse, extra: object = {}) => send(res, 200, { ok: true, ...extra });

async function peerArg(req: http.IncomingMessage, field: string): Promise<string | null> {
  return DB.resolveToId(requireString(await readJson(req), field, { max: MAX_PEER_IDENTIFIER }));
}

/** Counts one use of a daily quota; false once it is spent. */
async function withinDailyLimit(key: string, max: number): Promise<boolean> {
  return (await DB.bumpCounter(key, DAY_SECONDS)) <= max;
}

async function friendCapReached(id: string): Promise<boolean> {
  return (await DB.countFriends(id)) >= FRIEND_CAP;
}

/** C0 except tab and newline, DEL, C1. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the purpose
const REPORT_TEXT_CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/;

/**
 * The reporter's own note. Control characters other than tab and newline are
 * refused: the note is printed on the operator's terminal, where an escape
 * sequence could rewrite the queue or the clipboard.
 */
function reportNote(body: Record<string, unknown>): string | null {
  const value = optionalString(body, "note", { max: MAX_REPORT_NOTE });
  if (value !== null && REPORT_TEXT_CONTROL.test(value)) {
    throw new HttpError(400, "INVALID_FIELD", "note must not contain control characters");
  }
  return value;
}

/**
 * The quoted message. Its text is the reported person's, so a control
 * character in it must not make the report fail: each becomes U+FFFD.
 */
function reportExcerpt(body: Record<string, unknown>): string | null {
  const value = optionalString(body, "excerpt", { max: MAX_REPORT_EXCERPT });
  return value === null ? null : value.replace(new RegExp(REPORT_TEXT_CONTROL.source, "g"), "\ufffd");
}

function reportMessageId(body: Record<string, unknown>): string | null {
  const value = optionalString(body, "messageId", { max: MAX_REPORT_MESSAGE_ID_BYTES });
  if (value === null) return null;
  // C1 too: the database's [[:cntrl:]] check refuses it, and a 400 says why.
  const hasControl = [...value].some(
    (c) => c.charCodeAt(0) < 0x20 || (c.charCodeAt(0) >= 0x7f && c.charCodeAt(0) <= 0x9f),
  );
  if (Buffer.byteLength(value, "utf8") > MAX_REPORT_MESSAGE_ID_BYTES || hasControl) {
    throw new HttpError(400, "INVALID_FIELD", "messageId must be at most 128 bytes with no control characters");
  }
  return value;
}

/** The refusals `setUsername` names; any other error is not the client's to read. */
const USERNAME_REFUSALS = new Set(["USERNAME_RESERVED", "INVALID_USERNAME", "UNKNOWN_IDENTITY"]);

/** Routes that need a session, keyed by "METHOD path". */
const authenticated: Record<string, Route> = {
  "POST /username": async ({ req, res, id }) => {
    const username = requireString(await readJson(req), "username", { min: 3, max: 32 });
    try {
      await DB.setUsername(id, username, BOT_ID);
    } catch (e) {
      const code = (e as Error).message;
      if (code === "USERNAME_TAKEN") throw new HttpError(409, code, "That username is taken");
      if (USERNAME_REFUSALS.has(code)) throw new HttpError(400, code, "That username is not allowed");
      throw e; // anything else is a 500 with no detail
    }
    ok(res, { username });
  },

  "GET /friends": async ({ res, id }) => send(res, 200, { friends: await DB.getFriendsList(id) }),

  "GET /friends/invites": async ({ res, id }) => send(res, 200, { invites: await DB.getMyInvites(id) }),

  "POST /friends/invite": async ({ req, res, id }) => {
    if (await friendCapReached(id)) return send(res, 409, { error: "FRIEND_LIMIT", limit: FRIEND_CAP });
    if (!(await withinDailyLimit(`invite:day:${id}`, INVITES_PER_DAY))) {
      return send(res, 429, { error: "RATE_LIMITED", limit: INVITES_PER_DAY });
    }
    const to = requireString(await readJson(req), "to", { max: MAX_PEER_IDENTIFIER });
    const target = await DB.resolveToId(to);
    if (target && (await DB.isBlocked(id, target))) return send(res, 404, { error: "NOT_FOUND" });
    let toId: string;
    try {
      toId = await DB.invite(id, to);
    } catch (e) {
      const code = (e as Error).message;
      if (code === "NOT_FOUND") return send(res, 404, { error: code });
      if (code === "SELF_INVITE") throw new HttpError(400, code, "You cannot invite yourself");
      if (code === "ALREADY_FRIENDS") throw new HttpError(409, code, "You are already friends");
      throw e;
    }
    await EMQX.notifyGraphChanged([toId]);
    ok(res);
  },

  "POST /friends/accept": async ({ req, res, id }) => {
    if (await friendCapReached(id)) return send(res, 409, { error: "FRIEND_LIMIT", limit: FRIEND_CAP });
    const fromId = await peerArg(req, "from");
    if (!fromId) return send(res, 400, { ok: false });
    if (await DB.isBlocked(id, fromId)) return send(res, 404, { error: "NOT_FOUND" });
    // The cap is enforced again inside the accept, where concurrent accepts cannot race it.
    const outcome = await DB.acceptInvite(fromId, id, FRIEND_CAP);
    if (outcome === "full") return send(res, 409, { error: "FRIEND_LIMIT", limit: FRIEND_CAP });
    if (outcome === "peer-full") return send(res, 409, { error: "FRIEND_LIMIT", limit: FRIEND_CAP, peer: true });
    if (outcome === "no-invite") return send(res, 400, { ok: false });
    await EMQX.notifyGraphChanged([fromId, id]);
    const topics = await DB.getFriendshipTopics(id, fromId);
    ok(res, topics ? { friend: { id: fromId, convo_id: topics.convoId, handshake_id: topics.handshakeId } } : {});
  },

  "POST /friends/cancel": async ({ req, res, id }) => {
    const peer = await peerArg(req, "peer");
    const done = !!peer && ((await DB.cancelInvite(id, peer)) || (await DB.declineInvite(id, peer)));
    if (done && peer) await EMQX.notifyGraphChanged([peer, id]);
    send(res, done ? 200 : 400, { ok: done });
  },

  "POST /friends/remove": async ({ req, res, id }) => {
    const peer = await peerArg(req, "peer");
    const topics = peer ? await DB.removeFriendship(id, peer) : null;
    if (peer && topics) {
      await EMQX.revokeFriendshipTopics(id, peer, topics);
      await EMQX.notifyGraphChanged([peer, id]);
    }
    send(res, topics ? 200 : 400, { ok: !!topics });
  },

  "POST /friends/block": async ({ req, res, id }) => {
    const peer = await peerArg(req, "peer");
    if (!peer) return send(res, 404, { error: "NOT_FOUND" });
    if (peer === id) return send(res, 400, { error: "SELF_BLOCK" });
    await DB.block(id, peer);
    await DB.cancelInvite(id, peer);
    await DB.declineInvite(id, peer);
    const topics = await DB.removeFriendship(id, peer);
    if (topics) await EMQX.revokeFriendshipTopics(id, peer, topics);
    await EMQX.notifyGraphChanged([peer, id]);
    ok(res);
  },

  "POST /friends/unblock": async ({ req, res, id }) => {
    const peer = await peerArg(req, "peer");
    if (!peer) return send(res, 404, { error: "NOT_FOUND" });
    const lifted = await DB.unblock(id, peer);
    if (lifted) await EMQX.notifyGraphChanged([peer, id]);
    send(res, lifted ? 200 : 400, { ok: lifted });
  },

  "GET /friends/blocked": async ({ res, id }) => send(res, 200, { blocked: await DB.blockedIds(id) }),

  "POST /report": async ({ req, res, id }) => {
    if (!(await withinDailyLimit(`report:day:${id}`, REPORTS_PER_DAY))) {
      return send(res, 429, { error: "RATE_LIMITED", limit: REPORTS_PER_DAY });
    }
    const body = await readJson(req);
    const conversation = requireHex(body, "conversation", 32).toLowerCase();
    // An ended friendship still counts for a while, so unfriending first does not make abuse unreportable.
    const members = await DB.reportableMembers(conversation);
    if (members.length !== 2) return send(res, 404, { error: "NO_CONVERSATION" });
    if (!members.includes(id)) return send(res, 403, { error: "NOT_A_MEMBER" });
    const reportedId = members[0] === id ? members[1]! : members[0]!;
    if (requireString(body, "peer", { max: MAX_PEER_IDENTIFIER }).toLowerCase() !== reportedId) {
      return send(res, 400, { error: "PEER_MISMATCH", message: "peer is not the other member of that conversation" });
    }
    const category = requireString(body, "category", { max: 32 }).toLowerCase();
    if (!(REPORT_CATEGORIES as readonly string[]).includes(category)) {
      throw new HttpError(400, "INVALID_FIELD", `category must be one of: ${REPORT_CATEGORIES.join(", ")}`);
    }
    const reportId = await DB.createReport({
      reporterId: id,
      reportedId,
      conversationId: conversation,
      category: category as ReportCategory,
      note: reportNote(body),
      excerpt: reportExcerpt(body),
      frame: optionalBase64(body, "frame", MAX_REPORT_FRAME_BYTES),
      messageId: reportMessageId(body),
    });
    logger.event(`[report] filed ${reportId}: ${category} against ${reportedId.slice(0, 12)}…`);
    ok(res, { id: reportId });
  },

  "POST /prekeys": async ({ req, res, id }) => {
    if (!(await withinDailyLimit(`prekeys:day:${id}`, PREKEY_UPLOADS_PER_DAY))) {
      return send(res, 429, { error: "RATE_LIMITED", limit: PREKEY_UPLOADS_PER_DAY });
    }
    const body = await readJson(req);
    const medium = requireHex(body, "medium", HQC_PUBLIC_KEY_BYTES);
    const raw: unknown[] = Array.isArray(body.oneTime) ? body.oneTime : [];
    if (raw.length > MAX_ONETIME_PER_UPLOAD) {
      throw new HttpError(400, "TOO_MANY_PREKEYS", `at most ${MAX_ONETIME_PER_UPLOAD} one-time prekeys per upload`);
    }
    const oneTime = raw.map((entry, i) => {
      const item = entry as Record<string, unknown>;
      if (!Number.isInteger(item?.id) || (item.id as number) < 0 || (item.id as number) > MAX_PREKEY_ID) {
        throw new HttpError(400, "INVALID_FIELD", `oneTime[${i}].id must be an integer in 0..${MAX_PREKEY_ID}`);
      }
      return { id: item.id as number, prekey: requireHex(item, "prekey", HQC_PUBLIC_KEY_BYTES) };
    });
    ok(res, { accepted: await DB.putPrekeyBundle(id, medium, oneTime) });
  },

  "POST /prekeys/claim": async ({ req, res, id }) => {
    if ((await DB.bumpCounter(`prekeys:claim:${id}`, 60 * 60)) > PREKEY_CLAIMS_PER_HOUR) {
      return send(res, 429, { error: "RATE_LIMITED", limit: PREKEY_CLAIMS_PER_HOUR });
    }
    const peer = await peerArg(req, "peer");
    if (!peer || !(await DB.areFriends(id, peer))) return send(res, 403, { error: "NOT_FRIENDS" });
    // One friend cannot drain another's pool: past the per-pair allowance a
    // claim still gets the medium-term key, and the one-time keys stay for others.
    const pairClaims = await DB.bumpCounter(`prekeys:pair:${id}:${peer}`, ONETIME_CLAIM_WINDOW_SECONDS);
    const claimed = await DB.claimPrekey(peer, pairClaims <= ONETIME_CLAIMS_PER_PAIR);
    if (!claimed) return send(res, 404, { error: "NO_PREKEYS" });
    send(res, 200, claimed);
  },

  "GET /prekeys/count": async ({ res, id }) =>
    send(res, 200, {
      remaining: await DB.countOneTimePrekeys(id),
      maxId: await DB.maxOneTimePrekeyId(id),
      target: MAX_ONETIME_PER_UPLOAD,
    }),

  "POST /push/token": async ({ req, res, id }) => {
    const body = await readJson(req);
    const platform = requireString(body, "platform", { max: 16 });
    const environment = requireString(body, "environment", { max: 16 });
    if (platform !== "ios" && platform !== "macos")
      throw new HttpError(400, "INVALID_FIELD", "platform is ios or macos");
    if (environment !== "production" && environment !== "sandbox") {
      throw new HttpError(400, "INVALID_FIELD", "environment is production or sandbox");
    }
    const token = requireString(body, "token", { min: 8, max: 512 });
    await DB.setPushToken(id, platform as PushPlatform, environment as PushEnvironment, token);
    ok(res);
  },

  "POST /account/delete": async ({ req, res, id }) => {
    await DB.deleteUser(id);
    await DB.revokeSessionToken(bearer(req));
    await EMQX.kick(id);
    ok(res);
  },
};

/** Answers the routes that need no session; false when `url` is not one of them. */
async function publicRoute(res: http.ServerResponse, method: string, url: string) {
  if (method !== "GET") return false;
  if (url === "/info") {
    send(res, 200, { name: process.env.SERVER_NAME || "hqchat", version: process.env.SERVER_VERSION || "dev" });
  } else if (url.startsWith("/users")) {
    const username = new URL(url, "http://x").searchParams.get("username") || "";
    send(res, 200, { username, id: username ? await DB.getIdByUsername(username) : null });
  } else {
    const peerKey = url.match(/^\/peer\/([^/?]+)\/key$/);
    if (!peerKey) return false;
    const id = decodeURIComponent(peerKey[1]!).toLowerCase();
    if (!isPeerId(id))
      throw new HttpError(400, "INVALID_FIELD", `id must be ${core.PEER_ID_LENGTH} lowercase hex characters`);
    const publicKey = await DB.identityKey(id);
    if (publicKey) send(res, 200, { id, publicKey });
    else send(res, 404, { error: "UNKNOWN_PEER" });
  }
  return true;
}

function stripeWebhook(req: http.IncomingMessage, res: http.ServerResponse): void {
  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", async () => {
    try {
      const event = StripeService.constructEvent(Buffer.concat(chunks), String(req.headers["stripe-signature"] || ""));
      if (event.type === "checkout.session.completed") {
        const name = displayNameFromSession(event.data.object);
        if (name) await DB.recordSupporter(name);
      }
      res.writeHead(200).end("ok");
    } catch (e) {
      logger.error(`[stripe-webhook] ${(e as Error).message}`);
      res.writeHead(400).end("webhook error");
    }
  });
}

/** Every route of app-api, as a request listener. */
export function createApiHandler(): http.RequestListener {
  return async (req, res) => {
    const url = req.url || "";
    const method = req.method || "GET";
    try {
      if (DONATIONS_ENABLED && method === "POST" && url === "/stripe/webhook") return stripeWebhook(req, res);
      if (DONATIONS_ENABLED && (url.startsWith("/donate") || url.startsWith("/supporters"))) {
        return void handleDonate(req, res).catch((e: unknown) => {
          logger.error("[donate] handler error", e);
          if (!res.headersSent) res.writeHead(500).end("error");
        });
      }
      if (await publicRoute(res, method, url)) return;

      const route = authenticated[`${method} ${url}`];
      if (!route) return send(res, 404, { error: "not found" });
      const session = await DB.resolveSessionToken(bearer(req));
      if (!session) return send(res, 401, { error: "unauthenticated" });
      await route({ req, res, id: session.id });
    } catch (e) {
      if (e instanceof HttpError) return send(res, e.status, { error: e.code, message: e.message });
      logger.error(`[api] ${method} ${url}: ${(e as Error).message}`, e as Error);
      return send(res, 500, { error: "INTERNAL" });
    }
  };
}
