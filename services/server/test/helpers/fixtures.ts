import { createHash } from "node:crypto";
import { DB } from "../../src/server/db/api";
import { q } from "../../src/server/db/pg";

/** Records an identity and, when given, its username, bypassing the reserved-name rules. */
export async function createUser(id: string, identityPk: string, username?: string): Promise<void> {
  await DB.ensureUser(id, identityPk);
  if (username) await q(`UPDATE users SET username = $2 WHERE id = $1`, [id, username]);
}

/** A deterministic 64-hex topic id for a pair of clients. */
export function topicId(a: string, b: string): string {
  return createHash("sha256").update([a, b].sort().join("")).digest("hex");
}
