/** What the helper bot answers. Pure: the support address and randomness are injected. */

export interface ReplyDeps {
  supportEmail: string;
  /** Inclusive 1..max. Injected so the guessing game is testable. */
  randomInt?: (max: number) => number;
}

const HELP =
  "I can play simple games or answer basic questions. " +
  "Try '/game prc' for rock-paper-scissors or '/game guess <number>' to guess a number between 1 and 10. " +
  "'/ai' says how I can answer with AI, and what that shares.";

/** What /ai says: who answers, what is sent, what is kept. The site's /privacy and the app say the same. */
export const AI_ABOUT = [
  "the helper can answer with AI: Claude Haiku, by Anthropic. it's off until you send /ai on.",
  "",
  "when on, only the text you send in this chat goes to Anthropic to write a reply — never your other chats, contacts or keys. i keep the last few messages in memory to follow along; nothing is saved to disk, and /forget clears it. /ai off stops it.",
  "",
  "AI replies can be wrong.",
].join("\n");

export const AI_ON = "AI replies are on for this chat. /ai off turns them off; /forget clears what i remember.";
export const AI_OFF = "AI replies are off, and i've forgotten our conversation.";
export const AI_FORGOT = "done — i've forgotten our conversation.";
export const AI_UNAVAILABLE = "AI replies aren't available on this server.";
export const AI_NUDGE = "i can answer that with AI if you turn it on — /ai says what that means first.";
export const AI_BUSY = "one at a time — i'm still answering your last message.";
export const AI_TOO_LONG = "that's too long for me — try something shorter.";
export const AI_FAILED = "i can't answer that one right now — try /help.";
export const AI_LIMIT = {
  minute: "you're going a bit fast — try again in a minute.",
  day: "that's all the AI replies for today. they're back tomorrow.",
  global: "the AI is resting for today. it's back tomorrow.",
} as const;

const GAME_HELP = "I only play rock-paper-scissors or number guessing. Try '/game prc' or '/game guess <number>'.";

const GUESS_HELP = "I only play number guessing with '/game guess <number>'.";

export function gameReply(text: string, deps: ReplyDeps): string {
  const randomInt = deps.randomInt ?? ((max: number) => Math.floor(Math.random() * max) + 1);
  const lower = text.toLowerCase();

  if (lower.startsWith("/game prc")) {
    // The bot always wins, and says so.
    if (lower.includes("rock")) return "Paper! I win!";
    if (lower.includes("paper")) return "Scissors! I win!";
    if (lower.includes("scissors")) return "Rock! I win!";
    return "I only play rock-paper-scissors. Try sending 'rock', 'paper', or 'scissors'.";
  }

  if (lower.startsWith("/game guess")) {
    const parts = lower.split(" ");
    if (parts.length < 3) return GUESS_HELP;
    const raw = parts[2];
    if (raw === undefined) return GUESS_HELP;
    // The whole token must be digits; parseInt would accept "1abc" as 1.
    const number = /^\d+$/.test(raw) ? Number(raw) : NaN;
    if (Number.isNaN(number) || number < 1 || number > 10) return "Guess a number between 1 and 10.";
    const botNumber = randomInt(10);
    if (number === botNumber) return `You guessed ${number} and I guessed ${botNumber}. You win!`;
    return `You guessed ${number} and I guessed ${botNumber}. I win!`;
  }

  return GAME_HELP;
}

/** The answer to a command, or null when the text is not one. Commands never reach the AI. */
export function command(text: string, deps: ReplyDeps): string | null {
  const lower = text.toLowerCase();
  if (lower.startsWith("/support")) return `For support, please email ${deps.supportEmail}`;
  if (lower.startsWith("/game")) return gameReply(text, deps);
  if (lower.startsWith("/help")) return HELP;
  return null;
}

/** The answer without AI: commands, a greeting, or the text echoed back. */
export function reply(text: string, deps: ReplyDeps): string {
  if (text.toLowerCase().includes("hello")) return "Hello! I'm a bot. How can I help you?";
  return command(text, deps) ?? `You said: "${text}"`;
}
