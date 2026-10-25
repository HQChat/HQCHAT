/**
 * The sim node (`npm run sim`): SIM_COUNT synthetic users that talk, befriend
 * and echo through the public front door like a phone, and write an hourly
 * health report to `sim_reports` (see sim.ts, report.ts).
 *
 *   BASE_URL        the server's origin                     (http://127.0.0.1:8090)
 *   MQTT_URL        where WSS goes, when not `${BASE_URL}/mqtt` (a local stack)
 *   BOT_ID          the helper bot, which the sims never echo
 *   SIM_SEEDS       one 32-byte hex seed per line, one per sim; generated into
 *                   SIM_STATE_DIR when unset (in production a credential)
 *   SIM_PREFIX      handles are SIM_PREFIX01, SIM_PREFIX02, … (echo_)
 *   SIM_COUNT       how many sims                            (10)
 *   SIM_STATE_DIR   each sim's core state, and the fleet's   (./.sim)
 *   SIM_REPORT_MS   the report window                        (3600000)
 *   DATABASE_URL    a role that may insert into sim_reports
 *
 * Odd sims reach the broker over hqn/1 and even ones over WSS, so the report
 * compares the two.
 */

import "../common/config";
import * as path from "node:path";
import { idOfSeed, loadSeed, openBot } from "../bot/bot";
import { startHealthMonitor } from "../common/health-monitor";
import { logger } from "../common/logger";
import { initObservability } from "../common/observability";
import { q } from "../server/db/pg";
import { insertRows, Reporter } from "./report";
import { type Fleet, RealUsers, Sim } from "./sim";

const BASE_URL = (process.env.BASE_URL || "http://127.0.0.1:8090").replace(/\/$/, "");
const MQTT_URL = process.env.MQTT_URL || undefined;
const PREFIX = process.env.SIM_PREFIX || "echo_";
const COUNT = Number(process.env.SIM_COUNT || 10);
const STATE_DIR = process.env.SIM_STATE_DIR || path.join(process.cwd(), ".sim");
const REPORT_MS = Number(process.env.SIM_REPORT_MS || 3_600_000);

function main(): void {
  initObservability("sim");
  startHealthMonitor();
  if (!Number.isInteger(COUNT) || COUNT < 2 || COUNT > 99) throw new Error(`SIM_COUNT=${COUNT}: 2 to 99 sims`);
  if (!Number.isInteger(REPORT_MS) || REPORT_MS < 60_000)
    throw new Error(`SIM_REPORT_MS=${REPORT_MS}: at least a minute`);
  const given = (process.env.SIM_SEEDS || "").split(/\s+/).filter(Boolean);
  if (given.length > 0 && given.length < COUNT)
    throw new Error(`SIM_SEEDS has ${given.length} seeds for ${COUNT} sims`);
  for (const s of given)
    if (!/^[0-9a-f]{64}$/i.test(s)) throw new Error("SIM_SEEDS holds a seed that is not 32 bytes of hex");

  const profiles = Array.from({ length: COUNT }, (_, i) => {
    const handle = `${PREFIX}${String(i + 1).padStart(2, "0")}`;
    const dir = path.join(STATE_DIR, handle);
    return { handle, dir, seed: loadSeed(dir, given[i] ?? null), hqn: i % 2 === 0 };
  });
  const fleet: Fleet = {
    sims: new Map(profiles.map((p) => [idOfSeed(p.seed), p.handle])),
    botId: process.env.BOT_ID || null,
    realUsers: new RealUsers(path.join(STATE_DIR, "declined.json")),
  };
  if (!fleet.botId) logger.warn("[sim] BOT_ID is unset: the helper bot's messages would be echoed back to it");

  const sims = profiles.map((p) => {
    const client = openBot(p.dir, p.seed, {
      profileId: p.handle,
      serverUrl: BASE_URL,
      ...(MQTT_URL ? { wssUrl: MQTT_URL } : {}),
      hqn: p.hqn,
      log: (line) => logger.debug(`[sim ${p.handle}] ${line}`),
    });
    return new Sim(client, p.handle, p.hqn ? "hqn" : "wss", fleet);
  });
  for (const s of sims) s.start();
  new Reporter(sims, (rows) => insertRows(q, rows), REPORT_MS).start();
  logger.startup(`[sim] ${COUNT} sims (${PREFIX}01…) against ${BASE_URL}, reporting every ${REPORT_MS / 60_000} min`);
}

if (require.main === module) main();
