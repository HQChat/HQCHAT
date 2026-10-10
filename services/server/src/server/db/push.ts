import { one, q } from "./pg";

export type PushPlatform = "ios" | "macos";
export type PushEnvironment = "production" | "sandbox";

/** APNs device tokens. */
export const push = {
  async setPushToken(id: string, platform: PushPlatform, environment: PushEnvironment, token: string): Promise<void> {
    await q(
      `INSERT INTO push_tokens (id, platform, environment, token) VALUES ($1, $2, $3, $4)
       ON CONFLICT (id) DO UPDATE SET platform = EXCLUDED.platform, environment = EXCLUDED.environment,
                                      token = EXCLUDED.token, updated_at = now()
       WHERE (push_tokens.platform, push_tokens.environment, push_tokens.token)
             IS DISTINCT FROM (EXCLUDED.platform, EXCLUDED.environment, EXCLUDED.token)`,
      [id, platform, environment, token],
    );
  },

  async getPushToken(
    id: string,
  ): Promise<{ platform: PushPlatform; environment: PushEnvironment; token: string } | null> {
    return one<{ platform: PushPlatform; environment: PushEnvironment; token: string }>(
      `SELECT platform, environment, token FROM push_tokens WHERE id = $1`,
      [id],
    );
  },
};
