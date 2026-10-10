/**
 * Binding one HTTP handler to several addresses. Node binds one address per
 * server, so LISTEN_HOST="127.0.0.1,10.200.0.1" starts two servers; an empty
 * list means every interface.
 */

import type * as net from "node:net";

/** Parse a comma-separated host list. Empty means "every interface". */
export function parseHosts(value: string | undefined): (string | undefined)[] {
  const hosts = (value || "")
    .split(",")
    .map((h) => h.trim())
    .filter(Boolean);
  return hosts.length ? hosts : [undefined];
}

/**
 * Start one server per host from `make`, all on `port`. `onListening` runs once
 * per bound address. Returns the servers, so a caller or a test can close them.
 */
export function listenOn(
  make: () => net.Server,
  port: number,
  hosts: (string | undefined)[],
  onListening?: (host: string) => void,
): net.Server[] {
  return hosts.map((host) => {
    const server = make();
    server.listen(port, host, () => onListening?.(host ?? "*"));
    return server;
  });
}
