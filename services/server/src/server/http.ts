/** HTTP helpers shared by the routes: body parsing, validation, responses, request ids. */

import * as crypto from "node:crypto";
import type * as http from "node:http";

/** Max request body. Anything larger is refused before it is buffered. */
export const MAX_BODY_BYTES = 256 * 1024;

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message?: string,
  ) {
    super(message || code);
  }
}

/** A parsed JSON object body; read its fields through the require and optional helpers. */
export type JsonBody = Record<string, unknown>;

/**
 * Parses a JSON object body (an empty body is `{}`). The cap is in bytes and the
 * body is decoded once, so multi-byte characters split across chunks survive. An
 * oversized body is rejected with 413 and the rest is discarded rather than the
 * socket destroyed, so the response still reaches the client.
 */
export function readJson(req: http.IncomingMessage): Promise<JsonBody> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooBig = false;
    req.on("data", (c: Buffer) => {
      if (tooBig) return;
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        tooBig = true;
        reject(new HttpError(413, "BODY_TOO_LARGE"));
        chunks.length = 0;
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (tooBig) return;
      const data = Buffer.concat(chunks).toString("utf8");
      let body: unknown;
      try {
        body = data ? JSON.parse(data) : {};
      } catch {
        reject(new HttpError(400, "INVALID_JSON"));
        return;
      }
      if (typeof body === "object" && body !== null && !Array.isArray(body)) resolve(body as JsonBody);
      else reject(new HttpError(400, "INVALID_JSON", "the body must be a JSON object"));
    });
    req.on("error", reject);
  });
}

/**
 * A JSON response. Never stored by a cache: these carry session tokens, topic
 * capabilities and the friend graph.
 */
export function send(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
}

/** The bearer token from the Authorization header, or "". */
export function bearer(req: http.IncomingMessage): string {
  return (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
}

/**
 * The caller's request id, or a fresh one. Trusted only for correlation — it is
 * client-supplied, never an identity, and never used in a security decision.
 */
export function requestId(req: http.IncomingMessage): string {
  const given = String(req.headers["x-request-id"] || "").trim();
  if (/^[A-Za-z0-9_.:-]{1,64}$/.test(given)) return given;
  return crypto.randomUUID();
}

const TRUSTED_PROXY_HOPS = Number(process.env.TRUSTED_PROXY_HOPS || 1);

/**
 * The caller's IP from edge-set headers: CF-Connecting-IP, then X-Real-IP, then
 * X-Forwarded-For counted from the right by TRUSTED_PROXY_HOPS (the left end is
 * client-controlled).
 */
export function clientIp(req: http.IncomingMessage): string {
  if (process.env.TRUST_CF_CONNECTING_IP !== "false") {
    const cf = String(req.headers["cf-connecting-ip"] || "").trim();
    if (cf) return cf;
  }
  const realIp = String(req.headers["x-real-ip"] || "").trim();
  if (realIp) return realIp;

  const xff = String(req.headers["x-forwarded-for"] || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (xff.length) {
    const idx = Math.max(0, xff.length - TRUSTED_PROXY_HOPS);
    return xff[idx] ?? req.socket.remoteAddress ?? "unknown";
  }
  return req.socket.remoteAddress || "unknown";
}

/** The field when it is a string, else "" (never a coerced object or number). */
export function textField(body: JsonBody, field: string): string {
  const value = body[field];
  return typeof value === "string" ? value : "";
}

/** A required string field, trimmed and length-bounded. Throws HttpError(400). */
export function requireString(body: JsonBody, field: string, opts: { min?: number; max?: number } = {}): string {
  const { min = 1, max = 512 } = opts;
  const raw = body[field];
  if (typeof raw !== "string") throw new HttpError(400, "INVALID_FIELD", `${field} must be a string`);
  const value = raw.trim();
  if (value.length < min || value.length > max) {
    throw new HttpError(400, "INVALID_FIELD", `${field} must be ${min}–${max} characters`);
  }
  return value;
}

/** An optional string field: absent, null or empty is null; a non-string is a 400. */
export function optionalString(body: JsonBody, field: string, opts: { max?: number } = {}): string | null {
  const { max = 512 } = opts;
  const raw = body[field];
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "string") throw new HttpError(400, "INVALID_FIELD", `${field} must be a string`);
  const value = raw.trim();
  if (!value) return null;
  if (value.length > max) {
    throw new HttpError(400, "INVALID_FIELD", `${field} must be at most ${max} characters`);
  }
  return value;
}

/**
 * An optional base64 field, bounded in decoded bytes. Non-alphabet input is
 * rejected by re-encoding, since Buffer.from silently skips it.
 */
export function optionalBase64(body: JsonBody, field: string, maxBytes: number): Buffer | null {
  const raw = body[field];
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "string") throw new HttpError(400, "INVALID_FIELD", `${field} must be a base64 string`);
  if (!raw) return null;
  const buf = Buffer.from(raw, "base64");
  const unpadded = (s: string) => s.replace(/=+$/, "");
  if (unpadded(buf.toString("base64")) !== unpadded(raw)) {
    throw new HttpError(400, "INVALID_FIELD", `${field} must be base64`);
  }
  if (buf.length === 0) return null;
  if (buf.length > maxBytes) {
    throw new HttpError(400, "INVALID_FIELD", `${field} must decode to at most ${maxBytes} bytes`);
  }
  return buf;
}

/** A required lowercase-hex field of an exact byte length (public keys, hashes). */
export function requireHex(body: JsonBody, field: string, bytes: number): string {
  const value = requireString(body, field, { min: bytes * 2, max: bytes * 2 });
  if (!/^[0-9a-fA-F]+$/.test(value)) throw new HttpError(400, "INVALID_FIELD", `${field} must be hex`);
  return value;
}
