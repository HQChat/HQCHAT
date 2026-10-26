import "../common/config";
import * as crypto from "node:crypto";
import * as http from "node:http";
import { startHealthMonitor } from "@hqchat/common/health-monitor";
import { logger } from "@hqchat/common/logger";
import { initObservability } from "@hqchat/common/observability";
import { listenOn, parseHosts } from "../common/listen";
import { createApiHandler } from "./api";
import { createAuthHandler, INTERNAL_MQTT_USER } from "./auth";
import { assertServerConfig } from "./config";
import { requestId } from "./http";
import { startPushBridge } from "./push";
import { startWatch, watchStatus } from "./watch";

/**
 * The HQChat server: auth, the REST API, the push bridge and the broker watch
 * in one process, on one port.
 *
 *   GET  /health             { ok, version, broker: [unhealthy checks] }
 *   /auth/*, /mqtt/authn*    the auth service (src/server/auth.ts)
 *   everything else          the REST API (src/server/api.ts)
 *
 * The internal MQTT secret is generated at boot and shared only between the
 * auth hook and the push bridge in this process.
 */

const PORT = Number(process.env.PORT || 8090);
const VERSION = process.env.SERVER_VERSION || "dev";

/** Routes a request to /health, the auth service or the REST API. */
export function createServerHandler(parts: {
  auth: http.RequestListener;
  api: http.RequestListener;
  brokerProblems: () => string[];
}): http.RequestListener {
  return (req, res) => {
    // Echoed on every response, so a user can quote it in a report.
    res.setHeader("x-request-id", requestId(req));
    const url = req.url || "";
    if (req.method === "GET" && url === "/health") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, version: VERSION, broker: parts.brokerProblems() }));
      return;
    }
    if (url.startsWith("/auth/") || url.startsWith("/mqtt/authn")) return void parts.auth(req, res);
    return void parts.api(req, res);
  };
}

function main(): void {
  initObservability("server");
  assertServerConfig();

  const internalMqttSecret = crypto.randomBytes(32).toString("hex");
  const handler = createServerHandler({
    auth: createAuthHandler({ internalMqttSecret }),
    api: createApiHandler(),
    brokerProblems: () => watchStatus().unhealthy,
  });

  listenOn(
    () => http.createServer(handler),
    PORT,
    parseHosts(process.env.LISTEN_HOST),
    (host) => logger.startup(`server ${VERSION} listening on ${host}:${PORT}`),
  );

  startPushBridge({
    brokerUrl: process.env.EMQX_INTERNAL_URL || "mqtt://127.0.0.1:1884",
    username: INTERNAL_MQTT_USER,
    secret: internalMqttSecret,
  });
  startWatch();
  startHealthMonitor();
}

if (require.main === module) main();
