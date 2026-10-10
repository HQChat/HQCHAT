// The database API, one module per aggregate, behind a single `DB` facade.

import { logger } from "../../common/logger";
import { friends } from "./friends";
import { disconnect } from "./pg";
import { prekeys } from "./prekeys";
import { push } from "./push";
import { reports } from "./reports";
import { sessions } from "./sessions";
import { supporters } from "./supporters";
import { users } from "./users";

export type { FriendshipTopics } from "./friends";
export type { PushEnvironment, PushPlatform } from "./push";
export { REPORT_CATEGORIES, type ReportCategory } from "./reports";
export type { SessionInfo } from "./sessions";

export const DB = {
  ...users,
  ...supporters,
  ...friends,
  ...reports,
  ...prekeys,
  ...push,
  ...sessions,

  disconnect(): Promise<void> {
    return disconnect().catch((e: Error) => logger.warn(`[pg] close: ${e.message}`));
  },
};
