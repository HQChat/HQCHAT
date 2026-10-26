import { logger } from "@hqchat/common/logger";
import { assertConfig } from "../common/config";
import { donationSummary, donationsDead, resolvePrices } from "./donations-config";

/** Validates the server's configuration at boot; exits on what cannot work. */
export function assertServerConfig(): void {
  assertConfig(["stripe", "apns", "proxy"]);
  const prices = resolvePrices(process.env);
  if (/^(1|true|yes)$/i.test(process.env.DONATIONS_ENABLED || "") && donationsDead(prices)) {
    logger.error(`[server] ${donationSummary(prices)}`);
  }
  if (!process.env.BOT_ID) logger.warn("[server] BOT_ID is unset: new accounts are not befriended to the helper bot");
}
