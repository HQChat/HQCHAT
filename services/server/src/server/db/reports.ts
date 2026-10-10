import { one, q } from "./pg";

export const REPORT_CATEGORIES = ["spam", "harassment", "sexual", "violence", "csae", "other"] as const;
export type ReportCategory = (typeof REPORT_CATEGORIES)[number];

/** Content reports and their dispositions. */
export const reports = {
  /** Files a report and returns its id. */
  async createReport(r: {
    reporterId: string;
    reportedId: string;
    conversationId: string;
    category: ReportCategory;
    note?: string | null;
    excerpt?: string | null;
    frame?: Buffer | null;
    messageId?: string | null;
  }): Promise<string> {
    const row = await one<{ id: string }>(
      `INSERT INTO reports (reporter_id, reported_id, conversation_id, category,
                            reporter_note, message_excerpt, message_frame, message_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id::text AS id`,
      [
        r.reporterId,
        r.reportedId,
        r.conversationId,
        r.category,
        r.note ?? null,
        r.excerpt ?? null,
        r.frame ?? null,
        r.messageId ?? null,
      ],
    );
    if (!row) throw new Error("report insert returned no id");
    return row.id;
  },

  /** Unhandled reports, oldest first, after purging expired ones. */
  async listOpenReports(limit = 100): Promise<
    Array<{
      id: string;
      reporterId: string | null;
      reportedId: string;
      conversationId: string;
      category: string;
      note: string | null;
      excerpt: string | null;
      hasFrame: boolean;
      messageId: string | null;
      createdAt: string;
      againstSubject: number;
    }>
  > {
    await q(`DELETE FROM reports WHERE expires_at <= now()`);
    const res = await q<{
      id: string;
      reporter_id: string | null;
      reported_id: string;
      conversation_id: string;
      category: string;
      reporter_note: string | null;
      message_excerpt: string | null;
      has_frame: boolean;
      message_id: string | null;
      created_at: string;
      against_subject: number;
    }>(
      `SELECT r.id::text AS id, r.reporter_id, r.reported_id, r.conversation_id, r.category,
              r.reporter_note, r.message_excerpt, (r.message_frame IS NOT NULL) AS has_frame,
              r.message_id, r.created_at::text AS created_at,
              (SELECT count(*) FROM reports a WHERE a.reported_id = r.reported_id)::int AS against_subject
         FROM reports r
        WHERE r.handled_at IS NULL
        ORDER BY r.created_at
        LIMIT $1`,
      [Math.max(1, Math.min(1000, Math.floor(limit)))],
    );
    return res.rows.map((x) => ({
      id: x.id,
      reporterId: x.reporter_id,
      reportedId: x.reported_id,
      conversationId: x.conversation_id,
      category: x.category,
      note: x.reporter_note,
      excerpt: x.message_excerpt,
      hasFrame: x.has_frame,
      messageId: x.message_id,
      createdAt: x.created_at,
      againstSubject: x.against_subject,
    }));
  },

  /** Records a decision on an open report; returns the reported id, or null when the report is not open. */
  async resolveReport(id: string, disposition: string): Promise<string | null> {
    const res = await q<{ reported_id: string }>(
      `UPDATE reports SET handled_at = now(), disposition = $2
        WHERE id = $1::uuid AND handled_at IS NULL RETURNING reported_id`,
      [id, disposition],
    );
    return res.rows[0]?.reported_id ?? null;
  },
};
