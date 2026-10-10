import { disconnect, q } from "../src/server/db/pg";

/** Fails unless DATABASE_URL reaches a migrated database. Integration tests run it first. */
export async function requirePg(): Promise<void> {
  try {
    await q("SELECT 1 FROM users LIMIT 1");
  } catch (e) {
    throw new Error(`integration tests need a migrated Postgres at DATABASE_URL: ${(e as Error).message}`);
  }
}

/** Closes the pool once a file is done, so the test process can exit. */
export async function closePg(): Promise<void> {
  await disconnect();
}
