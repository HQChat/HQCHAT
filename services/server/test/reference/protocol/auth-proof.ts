import * as crypto from "node:crypto";

/**
 * The sign-in proof (v2), as core/hqchat-protocol/src/auth_proof.rs derives
 * it: HKDF-SHA256 of the shared secret the client decapsulates from the
 * server's challenge, bound to the origin it signs in at, its public key and
 * that challenge. The secret itself is never sent, so the exchange is not a
 * decryption oracle, and a server relaying the sign-in elsewhere gains nothing.
 */
const LABEL = Buffer.from("hqchat/v2/sign-in", "utf8");

/** `scheme://host[:port]`, lowercase, default port dropped; null for a non-http(s) URL. */
export function originOf(url: string): string | null {
  const m = /^(https?):\/\/([^/?#]*)/.exec(url.trim().toLowerCase());
  const scheme = m?.[1];
  const authority = m?.[2];
  if (!scheme || !authority || authority.includes("@")) return null;
  const port = scheme === "https" ? ":443" : ":80";
  return `${scheme}://${authority.endsWith(port) ? authority.slice(0, -port.length) : authority}`;
}

export function signInProof(ss: Buffer, origin: string, pk: Buffer, ct: Buffer): Buffer {
  const o = Buffer.from(origin, "utf8");
  if (o.length > 255) throw new Error("an origin is at most 255 bytes");
  const sha = (b: Buffer) => crypto.createHash("sha256").update(b).digest();
  const info = Buffer.concat([LABEL, Buffer.from([o.length]), o, sha(pk), sha(ct)]);
  return Buffer.from(crypto.hkdfSync("sha256", ss, LABEL, info, 32));
}
