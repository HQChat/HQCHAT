import { one, q } from "./pg";

/** Today in UTC, the day every count here is keyed by. */
const TODAY = `(now() AT TIME ZONE 'UTC')::date`;

/** The helper bot's id, which is never counted as a person. */
function botId(): string {
  return (process.env.BOT_ID || "").toLowerCase();
}

/**
 * The sim fleet's handles (`echo_01`, … — src/sim/main.ts, SIM_PREFIX), as a
 * Postgres regex. Sims are ordinary accounts to the server; their handle is
 * the only thing that tells them apart.
 */
export function simHandlePattern(): string {
  const prefix = process.env.SIM_PREFIX || "echo_";
  // Usernames are letters, digits and underscores, so a prefix outside that
  // cannot name a sim; match nothing rather than build a regex from it.
  if (!/^[A-Za-z0-9_]{1,24}$/.test(prefix)) return "^$";
  return `^${prefix}[0-9]{2,}$`;
}

/** One past day: accounts that signed in, and the most connected at once. */
export interface UsageDay {
  day: string;
  active: number;
  peakOnline: number;
}

/** What `hqcat-ops usage` prints, apart from the live online count. */
export interface UsageSummary {
  today: string;
  activeToday: number;
  peakOnlineToday: number;
  /** The seven days before today, oldest first; a day with no row is zeros. */
  lastWeek: UsageDay[];
  accounts: number;
  accountsToday: number;
}

/**
 * Usage as counts. `active_today` holds who signed in today, and only today:
 * `rollupUsage` turns each past day into a number and deletes its rows.
 */
export const usage = {
  /** Records that an account signed in today. The bot is never recorded. */
  async markActive(id: string): Promise<void> {
    if (!id || id === botId()) return;
    await q(`INSERT INTO active_today (id) VALUES ($1) ON CONFLICT DO NOTHING`, [id]);
  },

  /**
   * Turns every finished day in `active_today` into `usage_daily.active` and
   * deletes its rows, in one statement, so a row is counted exactly when it
   * is deleted. Sims, and ids that name no account, are left out of
   * the count. Returns the days rolled up.
   *
   * A sign-in that read the date just before midnight and commits just after
   * the rollup lands as a late row for that day and is added by the next run;
   * the same account can then count twice for that day. Midnight-wide, and a
   * count, not an audit.
   */
  async rollupUsage(): Promise<number> {
    const res = await q(
      `WITH gone AS (
         DELETE FROM active_today WHERE day < ${TODAY} RETURNING day, id
       ), counted AS (
         SELECT g.day, count(*) FILTER (WHERE u.username IS NULL OR u.username !~ $1)::int AS n
           FROM gone g JOIN users u ON u.id = g.id
          GROUP BY g.day
       )
       INSERT INTO usage_daily (day, active) SELECT day, n FROM counted
       ON CONFLICT (day) DO UPDATE SET active = usage_daily.active + EXCLUDED.active`,
      [simHandlePattern()],
    );
    return res.rowCount ?? 0;
  },

  /** Raises today's peak of people online to `n` if it is higher. */
  async notePeakOnline(n: number): Promise<void> {
    if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`online count ${n} is not a count`);
    await q(
      `INSERT INTO usage_daily (day, peak_online) VALUES (${TODAY}, $1)
       ON CONFLICT (day) DO UPDATE SET peak_online = GREATEST(usage_daily.peak_online, EXCLUDED.peak_online)`,
      [n],
    );
  },

  /** Ids that are connected but are not people: the bot and the sims. */
  async serviceIds(): Promise<Set<string>> {
    const res = await q<{ id: string }>(`SELECT id FROM users WHERE username ~ $1`, [simHandlePattern()]);
    const ids = new Set(res.rows.map((r) => r.id));
    if (botId()) ids.add(botId());
    return ids;
  },

  /** Today's counts, the week before and the account totals; bot and sims excluded. */
  async usageSummary(): Promise<UsageSummary> {
    const sims = simHandlePattern();
    const today = await one<{ today: string; active: number; peak: number }>(
      `SELECT ${TODAY}::text AS today,
              (SELECT count(*)::int FROM active_today a JOIN users u ON u.id = a.id
                WHERE a.day = ${TODAY} AND (u.username IS NULL OR u.username !~ $1)) AS active,
              COALESCE((SELECT peak_online FROM usage_daily WHERE day = ${TODAY}), 0) AS peak`,
      [sims],
    );
    const week = await q<{ day: string; active: number; peak: number }>(
      `SELECT d::date::text AS day, COALESCE(u.active, 0) AS active, COALESCE(u.peak_online, 0) AS peak
         FROM generate_series((${TODAY} - 7)::timestamp, (${TODAY} - 1)::timestamp, interval '1 day') d
         LEFT JOIN usage_daily u ON u.day = d::date
        ORDER BY d`,
    );
    const accounts = await one<{ total: number; today: number }>(
      `SELECT count(*)::int AS total,
              (count(*) FILTER (WHERE (created_at AT TIME ZONE 'UTC')::date = ${TODAY}))::int AS today
         FROM users
        WHERE id <> $1 AND (username IS NULL OR username !~ $2)`,
      [botId(), sims],
    );
    if (!today || !accounts) throw new Error("usage summary returned no row");
    return {
      today: today.today,
      activeToday: today.active,
      peakOnlineToday: today.peak,
      lastWeek: week.rows.map((r) => ({ day: r.day, active: r.active, peakOnline: r.peak })),
      accounts: accounts.total,
      accountsToday: accounts.today,
    };
  },

  /** Days already cached in `app_downloads` from `since` on, as YYYY-MM-DD. */
  async downloadDaysSince(since: string): Promise<Set<string>> {
    const res = await q<{ day: string }>(`SELECT day::text AS day FROM app_downloads WHERE day >= $1::date`, [since]);
    return new Set(res.rows.map((r) => r.day));
  },

  /** Caches one day's first-time download units. */
  async recordDownloads(day: string, units: number): Promise<void> {
    if (!Number.isSafeInteger(units) || units < 0) throw new RangeError(`download units ${units} are not a count`);
    await q(
      `INSERT INTO app_downloads (day, units) VALUES ($1::date, $2)
       ON CONFLICT (day) DO UPDATE SET units = EXCLUDED.units`,
      [day, units],
    );
  },

  /** The latest cached day and the sum of every cached day. */
  async downloadTotals(): Promise<{ latest: { day: string; units: number } | null; total: number }> {
    const latest = await one<{ day: string; units: number }>(
      `SELECT day::text AS day, units FROM app_downloads ORDER BY day DESC LIMIT 1`,
    );
    const sum = await one<{ total: string }>(`SELECT COALESCE(sum(units), 0)::text AS total FROM app_downloads`);
    return { latest, total: Number(sum?.total ?? 0) };
  },
};
