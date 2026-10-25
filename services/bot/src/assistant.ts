/**
 * The helper's AI replies, from Claude Haiku. Only text a user sent the
 * helper after `/ai on` reaches it (bot.ts decides); this module makes the
 * call and turns every way it can fail into a reason the bot answers with a
 * fixed line.
 *
 *   ANTHROPIC_API_KEY_PATH   a file holding the key (systemd's credential);
 *                            unset, AI replies are off
 *
 * The key is read from that file and handed to the SDK, never put in the
 * environment: the name does not end in `_FILE`, so the `*_FILE` convention
 * (common/file-env.ts) leaves it alone, and an ANTHROPIC_API_KEY variable is
 * refused in production.
 */

import * as fs from "node:fs";
import Anthropic from "@anthropic-ai/sdk";
import { logger } from "@hqchat/common/logger";

export const MODEL = "claude-haiku-5-5";
/** Room for the model's thinking as well as the short reply. */
const MAX_TOKENS = 1024;
const TIMEOUT_MS = 15_000;

/** Public like the rest of the repository: it holds nothing secret. */
export const SYSTEM = `You are "helper", the account every new HQChat user starts with, answering in a chat bubble.

About HQChat: end-to-end encrypted one-to-one messaging with post-quantum cryptography (HQC). Keys exist only on the user's device: the server relays messages and cannot read them, and nobody can recover lost keys or history. People add friends by username. Donations unlock no feature. The apps and the server are open source.

About you: you are an AI (Claude Haiku, by Anthropic). You only see this one chat, and only since the user turned AI replies on. You cannot see other chats, contacts or keys, and you cannot act on anyone's account. You keep the last few messages in memory; /forget clears them and /ai off stops AI replies. Other commands: /help, /game, /support.

How to answer: short, plain text, lowercase like the rest of the helper's messages, no markdown. Say so when you are not sure. Never ask for passwords, keys or codes. For account or app problems, point to /support.`;

/** The one call the assistant makes: the SDK's client in production, a fake in tests. */
export type CreateMessage = (body: Anthropic.MessageCreateParamsNonStreaming) => Promise<Anthropic.Message>;

export type Answer = { ok: true; text: string } | { ok: false; reason: "refusal" | "cut" | "empty" | "error" | "off" };

export class Assistant {
  /** Set when the key is refused: no further calls until a restart. */
  private off = false;

  constructor(private readonly create: CreateMessage) {}

  async answer(history: readonly Anthropic.MessageParam[], text: string): Promise<Answer> {
    if (this.off) return { ok: false, reason: "off" };
    let response: Anthropic.Message;
    try {
      response = await this.create({
        model: MODEL,
        max_tokens: MAX_TOKENS,
        system: SYSTEM,
        output_config: { effort: "low" },
        messages: [...history, { role: "user", content: text }],
      });
    } catch (e) {
      // Most specific first; APIConnectionError (timeouts included) is an APIError.
      if (e instanceof Anthropic.AuthenticationError || e instanceof Anthropic.PermissionDeniedError) {
        this.off = true;
        logger.error(`[bot] the Anthropic key was refused (${e.status}): AI replies are off until a restart`);
      } else if (e instanceof Anthropic.RateLimitError) {
        logger.warn("[bot] Anthropic rate limit reached");
      } else if (e instanceof Anthropic.APIConnectionError) {
        logger.warn(`[bot] Anthropic unreachable: ${e.message}`);
      } else if (e instanceof Anthropic.APIError) {
        logger.warn(`[bot] Anthropic answered ${e.status}: ${e.message}`);
      } else {
        logger.error(`[bot] the AI call failed: ${(e as Error).message}`);
      }
      return { ok: false, reason: "error" };
    }
    if (response.stop_reason === "refusal") return { ok: false, reason: "refusal" };
    if (response.stop_reason === "max_tokens") return { ok: false, reason: "cut" };
    // A response can open with thinking blocks: the reply is its text blocks.
    const out = response.content
      .flatMap((b) => (b.type === "text" ? [b.text] : []))
      .join("")
      .trim();
    return out ? { ok: true, text: out } : { ok: false, reason: "empty" };
  }
}

/** The assistant when the deployment gives the bot a key; undefined, AI replies are off. */
export function openAssistant(env: NodeJS.ProcessEnv = process.env): Assistant | undefined {
  if (env.ANTHROPIC_API_KEY) {
    const why = "ANTHROPIC_API_KEY is set: give the key as a file through ANTHROPIC_API_KEY_PATH";
    if (env.NODE_ENV === "production") throw new Error(why);
    logger.warn(`[bot] ${why}; the variable is ignored`);
  }
  const file = env.ANTHROPIC_API_KEY_PATH;
  if (!file) return undefined;
  let apiKey: string;
  try {
    apiKey = fs.readFileSync(file, "utf8").trim();
  } catch (e) {
    logger.error(
      `[bot] ANTHROPIC_API_KEY_PATH=${file} could not be read (${(e as Error).message}): AI replies are off`,
    );
    return undefined;
  }
  if (!apiKey) {
    logger.error(`[bot] ANTHROPIC_API_KEY_PATH=${file} is empty: AI replies are off`);
    return undefined;
  }
  const client = new Anthropic({ apiKey, timeout: TIMEOUT_MS, maxRetries: 2 });
  return new Assistant((body) => client.messages.create(body));
}
