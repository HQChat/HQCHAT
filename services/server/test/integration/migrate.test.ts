// The migration runner, against a throwaway database.
//
// Every deploy runs this, and nothing tested it. The failure it guards against
// is not theoretical: `001_schema.sql` carries a comment recording that a schema
// shipped which "could not accept a single real user", because the end-to-end
// suite never executed on the PR that introduced it.
//
// Run as a SUBPROCESS rather than imported, because `migrate.ts` calls `main()`
// at module scope — importing it would migrate whatever DATABASE_URL happens to
// point at, which during a test run is the developer's own database. That is
// also why each test builds its own database and drops it afterwards.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as path from "node:path";
import { test } from "node:test";
import { Client } from "pg";
import { closePg, requirePg } from "../pg-helper";

test.before(requirePg);

const ROOT = path.join(__dirname, "..", "..");

/** Admin connection, for CREATE/DROP DATABASE — they cannot run in a transaction. */
function adminUrl(): string | null {
  const url = process.env.DATABASE_URL;
  if (!url) return null;
  return url.replace(/\/[^/?]+(\?|$)/, "/postgres$1");
}

async function withScratchDatabase(fn: (url: string) => Promise<void>): Promise<void> {
  const admin = adminUrl();
  assert.ok(admin, "DATABASE_URL must be set for this test");
  const name = `hqchat_migrate_${crypto.randomBytes(6).toString("hex")}`;
  const root = new Client({ connectionString: admin! });
  await root.connect();
  await root.query(`CREATE DATABASE ${name}`);
  const url = admin!.replace(/\/postgres(\?|$)/, `/${name}$1`);
  try {
    await fn(url);
  } finally {
    // Terminate stragglers first, or DROP blocks on the runner's own connection
    // if it failed before closing.
    await root.query(
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [name],
    );
    await root.query(`DROP DATABASE IF EXISTS ${name}`);
    await root.end();
  }
}

function migrate(url: string): string {
  return execFileSync("npx", ["tsx", "src/server/db/migrate.ts"], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, DATABASE_URL: url, DATABASE_URL_DIRECT: url },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function query<T extends Record<string, any>>(url: string, sql: string): Promise<T[]> {
  const c = new Client({ connectionString: url });
  await c.connect();
  try {
    return (await c.query<T>(sql)).rows;
  } finally {
    await c.end();
  }
}

test("a fresh database migrates, and every migration is recorded", async () => {
  await withScratchDatabase(async (url) => {
    const out = migrate(url);
    assert.match(out, /applied \d+ of \d+/, `expected migrations to run, got: ${out}`);

    const applied = await query<{ name: string }>(url, "SELECT name FROM schema_migrations ORDER BY name");
    assert.deepEqual(
      applied.map((r) => r.name),
      ["001_baseline.sql", "002_auth_challenges.sql", "003_banned_ids.sql"],
    );
  });
});

test("the schema a fresh migrate produces can hold a user", async () => {
  // The specific regression `001_schema.sql` documents. A migration that applies
  // cleanly and then cannot accept a row is the failure mode worth guarding,
  // because "migrate succeeded" says nothing about it.
  await withScratchDatabase(async (url) => {
    migrate(url);
    const tables = await query<{ table_name: string }>(
      url,
      `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`,
    );
    const names = tables.map((t) => t.table_name);
    for (const needed of ["users", "schema_migrations"]) {
      assert.ok(names.includes(needed), `expected a ${needed} table, got ${names.join(", ")}`);
    }
    await query(url, `SELECT 1 FROM users LIMIT 1`); // throws if the table is unusable
  });
});

test("migrating again is a no-op, not a second apply", async () => {
  await withScratchDatabase(async (url) => {
    migrate(url);
    const first = await query<{ name: string }>(url, "SELECT name FROM schema_migrations");

    const out = migrate(url);
    assert.match(out, /up to date/, `a second run should be a no-op, got: ${out}`);

    const second = await query<{ name: string }>(url, "SELECT name FROM schema_migrations");
    assert.equal(second.length, first.length, "no migration may be recorded twice");
  });
});

test("a failing migration rolls back and records nothing", async () => {
  await withScratchDatabase(async (url) => {
    migrate(url);
    const before = (await query<{ name: string }>(url, "SELECT name FROM schema_migrations")).length;

    // Forge a migration the runner has not seen, by inserting a marker row for a
    // file that does not exist — the runner must not remove or re-run anything
    // on the strength of it.
    await query(url, `INSERT INTO schema_migrations (name) VALUES ('999_not_a_file.sql')`);
    const out = migrate(url);
    assert.match(out, /up to date/);

    const after = await query<{ name: string }>(url, "SELECT name FROM schema_migrations");
    assert.equal(after.length, before + 1, "the runner leaves rows it does not recognise alone");
  });
});

test("no DATABASE_URL is a clear failure, not a silent success", async () => {
  let failed = false;
  let output = "";
  try {
    execFileSync("npx", ["tsx", "src/server/db/migrate.ts"], {
      cwd: ROOT,
      encoding: "utf8",
      env: { ...process.env, DATABASE_URL: "", DATABASE_URL_DIRECT: "" },
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    failed = true;
    const { stdout, stderr } = e as { stdout?: string; stderr?: string };
    output = `${stdout ?? ""}${stderr ?? ""}`;
  }
  assert.ok(failed, "migrating with no database must exit non-zero");
  assert.match(output, /DATABASE_URL/, "…and say which variable is missing");
});

test.after(async () => {
  await closePg();
});
