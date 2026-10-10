import * as fs from "node:fs";
import { apnsGaps, apnsIntended, apnsSummary } from "../server/apns-config";
import { donationGaps, donationSummary, resolvePrices } from "../server/donations-config";

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

/** Whether this deployment takes donations through Stripe. */
export const DONATIONS_ENABLED = /^(1|true|yes)$/i.test(process.env.DONATIONS_ENABLED || "");

export type ConfigNeed = "stripe" | "apns";

/**
 * Validates the configuration a service needs and exits with every problem
 * listed at once. Warnings (e.g. APNs not configured) are printed, not fatal.
 */
export function assertConfig(needs: ConfigNeed[] = []): void {
  const errors: string[] = [];
  const warnings: string[] = [];
  const required = (name: string, why: string) => {
    if (!process.env[name]?.trim()) errors.push(`${name} is required (${why}).`);
  };

  required("DATABASE_URL", "every service reads and writes Postgres");

  if (DONATIONS_ENABLED && needs.includes("stripe")) {
    required("STRIPE_SECRET_KEY", "DONATIONS_ENABLED=1");
    required("STRIPE_WEBHOOK_SECRET", "DONATIONS_ENABLED=1");
    required("PUBLIC_BASE_URL", "Stripe redirect URLs");
    const prices = resolvePrices(process.env);
    if (donationGaps(prices).length) warnings.push(donationSummary(prices));
  }

  if (needs.includes("apns") && apnsGaps(process.env).length) {
    warnings.push(
      apnsIntended(process.env)
        ? `APNs is partially configured, missing ${apnsGaps(process.env).join(", ")}`
        : apnsSummary(process.env),
    );
  }

  const databaseUrl = process.env.DATABASE_URL || "";
  if (process.env.NODE_ENV === "production" && databaseUrl) {
    if (!/sslmode=verify-full/.test(databaseUrl)) warnings.push("DATABASE_URL does not request sslmode=verify-full.");
    if (!process.env.PGSSLROOTCERT?.trim()) warnings.push("PGSSLROOTCERT is unset; the cluster CA cannot be verified.");
  }

  for (const w of warnings) console.warn(`config: ${w}`);
  if (errors.length) {
    console.error(`invalid configuration, refusing to start:\n  - ${errors.join("\n  - ")}`);
    process.exit(1);
  }
}
