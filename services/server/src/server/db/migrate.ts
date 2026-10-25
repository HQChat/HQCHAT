/**
 * Applies `migrations/*.sql` in filename order, each in its own transaction,
 * recording them in `schema_migrations`; applied files are never re-run.
 * Connects to DATABASE_URL_DIRECT (DDL bypasses the transaction pooler), else
 * DATABASE_URL. `${APP_ROLE}` in a file is replaced with APP_ROLE, defaulting
 * to the connecting user.
 */

import "../../common/config";
import * as fs from "node:fs";
import * as path from "node:path";
import { logger } from "@hqchat/common/logger";
import { Client } from "pg";
import { tls, withoutSslMode } from "./ssl";

const DIR = path.join(__dirname, "migrations");

function roles(fallback: string) {
  const named = (name: string) => {
    const v = (process.env[name] || fallback).trim();
    // Interpolated into SQL, so it must be a plain identifier.
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(v)) {
      throw new Error(`${name}="${v}" is not a plain SQL identifier`);
    }
    return v;
  };
  return { APP_ROLE: named("APP_ROLE") };
}

async function main() {
  const url = process.env.DATABASE_URL_DIRECT || process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL_DIRECT (or DATABASE_URL) is required");

  const client = new Client({
    connectionString: withoutSslMode(url),
    ssl: tls(url),
  });

  await client.connect();

  const who = (await client.query<{ u: string }>("SELECT current_user AS u")).rows[0]?.u;
  if (!who) throw new Error("could not resolve current_user");
  const subs = roles(who);

  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name       text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);

  const applied = new Set(
    (await client.query<{ name: string }>("SELECT name FROM schema_migrations")).rows.map((r) => r.name),
  );

  const files = fs
    .readdirSync(DIR)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  let ran = 0;

  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = fs
      .readFileSync(path.join(DIR, file), "utf8")
      .replace(/\$\{(APP_ROLE)\}/g, (_, k: keyof typeof subs) => subs[k]);

    logger.startup(`[migrate] applying ${file}`);
    try {
      await client.query("BEGIN");
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [file]);
      await client.query("COMMIT");
      ran++;
    } catch (e) {
      await client.query("ROLLBACK").catch(() => {});
      throw new Error(`${file}: ${(e as Error).message}`);
    }
  }

  logger.startup(
    ran === 0 ? `[migrate] up to date (${files.length} migrations)` : `[migrate] applied ${ran} of ${files.length}`,
  );
  await client.end();
}

main().catch((e) => {
  logger.error(`[migrate] failed: ${(e as Error).message}`);
  process.exit(1);
});
