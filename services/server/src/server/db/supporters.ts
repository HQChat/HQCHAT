import { q } from "./pg";

/** Opt-in supporter names shown on the donation page. */
export const supporters = {
  /** Records an opt-in supporter name; a repeat donor keeps their first date. */
  async recordSupporter(displayName: string): Promise<void> {
    const name = displayName.trim().slice(0, 60);
    if (!name) return;
    await q(
      `INSERT INTO supporters (name_key, display_name) VALUES ($1, $2)
       ON CONFLICT (name_key) DO UPDATE SET display_name = EXCLUDED.display_name`,
      [name.toLowerCase(), name],
    );
  },

  /** Supporters, oldest first. */
  async listSupporters(): Promise<Array<{ name: string; since: string }>> {
    const res = await q<{ display_name: string; first_seen: string }>(
      `SELECT display_name, first_seen::text FROM supporters ORDER BY first_seen, name_key`,
    );
    return res.rows.map((r) => ({ name: r.display_name, since: r.first_seen }));
  },
};
