/**
 * noise-gw entrypoint: hqn/1 in front of EMQX's internal plain-TCP listener.
 * See gateway.ts for the threat model; the protocol is the core's
 * (core/hqchat-protocol/src/noise.rs).
 *
 *   NOISE_GW_PORT         client listen port                     (8443)
 *   NOISE_GW_HOST         client listen address           (every interface)
 *   NOISE_GW_HEALTH_PORT  /health and /keys                      (8081)
 *   NOISE_GW_HEALTH_HOST  comma-separated addresses for it  (every interface)
 *   NOISE_KEYS_FILE       secret seeds, see keys.ts              (required)
 *   EMQX_TCP_HOST/PORT    the broker's internal TCP listener  (127.0.0.1:1883)
 *   NOISE_GW_WORKERS      decapsulation workers         (cpus - 1, at least 1)
 *   NOISE_GW_QUEUE        decapsulations allowed to wait            (64)
 */

import "../common/config";
import * as http from "node:http";
import * as os from "node:os";
import { startHealthMonitor } from "../common/health-monitor";
import { listenOn, parseHosts } from "../common/listen";
import { logger } from "../common/logger";
import { initObservability } from "../common/observability";
import { DecapPool } from "./decap-pool";
import { createGateway } from "./gateway";
import { decapsulationKeys, loadServerKeys, publicKeys, readKeySeeds } from "./keys";

if (require.main === module) {
  initObservability("noise-gw");
  const port = Number(process.env.NOISE_GW_PORT || 8443);
  const healthPort = Number(process.env.NOISE_GW_HEALTH_PORT || process.env.PORT || 8081);
  const keysFile = process.env.NOISE_KEYS_FILE;
  if (!keysFile) throw new Error("NOISE_KEYS_FILE is required");
  const seeds = readKeySeeds(keysFile);
  const keys = loadServerKeys(seeds);
  const pool = new DecapPool(
    decapsulationKeys(seeds),
    Number(process.env.NOISE_GW_WORKERS || Math.max(1, os.cpus().length - 1)),
    Number(process.env.NOISE_GW_QUEUE || 64),
  );

  const { server, stats } = createGateway({
    keys,
    decapsulate: (keyId, ct) => pool.decapsulate(keyId, ct),
    upstream: { host: process.env.EMQX_TCP_HOST || "127.0.0.1", port: Number(process.env.EMQX_TCP_PORT || 1883) },
    onEvent: (e) => {
      // Refusals are routine on a public listener: counted, never logged as errors.
      if (e.t === "established")
        logger.debug(`[noise-gw] ${e.clientId?.slice(0, 12) ?? "?"}… from ${e.ip} in ${e.handshakeMs}ms`);
    },
  });
  const host = process.env.NOISE_GW_HOST || undefined;
  server.listen(port, host, () => {
    logger.startup(
      `🔒 noise-gw on ${host ?? "*"}:${port} — keys ${[...keys.keys()].join(",")}, ${pool.size} decap workers`,
    );
  });

  // /health and /keys: loopback and the WireGuard address, never the public one.
  listenOn(
    () =>
      http.createServer((req, res) => {
        if (req.url === "/health") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true, service: "noise-gw", ...stats(), decapQueued: pool.queued }));
          return;
        }
        if (req.url === "/keys") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ keys: publicKeys(keys) }));
          return;
        }
        res.writeHead(404).end();
      }),
    healthPort,
    parseHosts(process.env.NOISE_GW_HEALTH_HOST),
  );

  startHealthMonitor();
}
