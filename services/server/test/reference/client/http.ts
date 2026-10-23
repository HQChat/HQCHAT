/** A non-2xx answer from the server: its status and the `error` code it named. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Sends a JSON request and returns the parsed body; throws ApiError on a non-2xx. */
export async function requestJson<T = Record<string, unknown>>(
  url: string,
  opts: { method?: string; body?: unknown; bearer?: string } = {},
): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { "user-agent": "hqchat-client/1" };
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  if (opts.bearer) headers.authorization = `Bearer ${opts.bearer}`;
  const res = await fetch(url, {
    method,
    headers,
    ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
    signal: AbortSignal.timeout(15_000),
  });
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }
  if (!res.ok) {
    const code = typeof (body as { error?: unknown })?.error === "string" ? (body as { error: string }).error : "";
    throw new ApiError(res.status, code, `${method} ${new URL(url).pathname} → ${res.status} ${code}`.trim());
  }
  return body as T;
}
