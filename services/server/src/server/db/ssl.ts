/** TLS settings for Postgres, shared by the pool and the migrator. */
import * as fs from "node:fs";

/** The cluster CA from PGSSLROOTCERT, or "" when unset, missing or empty. */
export function clusterCa(): string {
  const path = process.env.PGSSLROOTCERT;
  return path && fs.existsSync(path) ? fs.readFileSync(path, "utf8").trim() : "";
}

/** Whether the URI names this machine (loopback or a Unix socket), where plaintext stays on the host. */
export function isLocal(uri: string | undefined): boolean {
  if (!uri || /[?&]host=\//.test(uri)) return true;
  let host: string;
  try {
    host = new URL(uri).hostname.replace(/^\[|\]$/g, "");
  } catch {
    return false;
  }
  return host === "" || host === "localhost" || host === "::1" || host.startsWith("127.");
}

/**
 * Verify certificate and hostname against the cluster CA when there is one
 * (DigitalOcean's `sslmode=verify-full`). Plaintext only to a database on this
 * machine: a remote one without a CA is refused rather than reached in clear.
 */
export function tls(uri: string | undefined): { ca: string; rejectUnauthorized: true } | false {
  const ca = clusterCa();
  if (ca) return { ca, rejectUnauthorized: true };
  if (isLocal(uri)) return false;
  throw new Error("a remote database needs its CA in PGSSLROOTCERT; refusing a plaintext connection");
}

/**
 * The URI without `sslmode`. node-postgres lets the URI's sslmode override the
 * explicit `ssl` object, replacing the cluster CA with the system trust store,
 * which does not contain DigitalOcean's per-project CA.
 */
export function withoutSslMode(uri: string | undefined): string | undefined {
  if (!uri) return uri;
  return uri.replace(/([?&])sslmode=[^&]*&?/, (_m, sep: string) => (sep === "?" ? "?" : "&")).replace(/[?&]$/, "");
}
