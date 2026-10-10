import * as http from "node:http";
import type { AddressInfo } from "node:net";

/** A response: the status, the body parsed as JSON (undefined when it is not), and the raw text. */
export interface Reply {
  status: number;
  body: any;
  text: string;
}

/** What to send: a JSON `body`, or `raw` bytes sent as-is, plus a bearer `token` and extra headers. */
export interface CallOptions {
  body?: unknown;
  raw?: string;
  token?: string;
  headers?: Record<string, string>;
}

/** The port a listening server was given. */
export function portOf(server: http.Server): number {
  return (server.address() as AddressInfo).port;
}

/** Serves `handler` on an ephemeral loopback port for one request and returns the reply. */
export async function call(
  handler: http.RequestListener,
  method: string,
  path: string,
  opts: CallOptions = {},
): Promise<Reply> {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  try {
    const json = opts.raw === undefined && opts.body !== undefined;
    const payload =
      opts.raw !== undefined ? Buffer.from(opts.raw) : json ? Buffer.from(JSON.stringify(opts.body)) : null;
    const headers: Record<string, string> = {
      ...(json ? { "content-type": "application/json" } : {}),
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      ...opts.headers,
    };
    return await new Promise<Reply>((resolve, reject) => {
      const req = http.request(
        { port: portOf(server), host: "127.0.0.1", method, path, agent: false, headers },
        (res) => {
          const parts: Buffer[] = [];
          res.on("data", (d: Buffer) => parts.push(d));
          res.on("end", () => {
            const text = Buffer.concat(parts).toString("utf8");
            let body: unknown;
            try {
              body = JSON.parse(text);
            } catch {
              body = undefined;
            }
            resolve({ status: res.statusCode ?? 0, body, text });
          });
        },
      );
      req.on("error", reject);
      req.end(payload ?? undefined);
    });
  } finally {
    server.close();
  }
}
