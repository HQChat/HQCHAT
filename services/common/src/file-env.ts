import * as fs from "node:fs";

/**
 * Process configuration. Importing this module resolves the `*_FILE`
 * convention: for every `FOO_FILE` naming a readable file, `FOO` is set to its
 * trimmed contents unless `FOO` is already set. systemd hands credentials to the
 * services this way (`FOO_FILE=$CREDENTIALS_DIRECTORY/foo`).
 */
for (const key of Object.keys(process.env)) {
  if (!key.endsWith("_FILE")) continue;
  const base = key.slice(0, -"_FILE".length);
  const path = process.env[key];
  if (process.env[base] || !path) continue;
  try {
    process.env[base] = fs.readFileSync(path, "utf8").trim();
  } catch (err) {
    console.error(`config: ${key}=${path} could not be read: ${(err as Error).message}`);
  }
}
