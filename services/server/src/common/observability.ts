/**
 * Sentry and process-level crash capture. `initObservability` must run first in
 * an entrypoint: it initialises Sentry when SENTRY_DSN is set, routes the
 * logger's breadcrumbs and events to it, and installs handlers that report an
 * uncaught exception and exit (systemd restarts the unit), report unhandled
 * rejections and process warnings, and flush on SIGTERM/SIGINT.
 */

import * as Sentry from "@sentry/node";
import { logger, registerSentrySink } from "./logger";
import { scrubBreadcrumb, scrubEvent } from "./scrub";

let started = false;
let sentryOn = false;

export function sentryEnabled(): boolean {
  return sentryOn;
}

/** Which process is reporting; tags every Sentry event. */
export type Component = "server" | "bot" | "sim" | "noise-gw";

/** Initialises Sentry and the crash handlers once per process. */
export function initObservability(component: Component): void {
  if (started) return;
  started = true;

  const isProd = process.env.NODE_ENV === "production";
  // No DSN is built into the code, so a local run or a test never reports
  // anywhere. A deployment embeds SENTRY_DSN from its environment file
  // (infra/environments/<name>.json → the host's unit environment).
  const dsn = process.env.SENTRY_DSN || "";

  sentryOn = !!dsn && process.env.SENTRY_ENABLED !== "false";

  if (sentryOn) {
    const release = process.env.SENTRY_RELEASE || process.env.SERVER_VERSION;
    Sentry.init({
      dsn,
      environment: process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || "development",
      ...(release ? { release } : {}),
      tracesSampleRate: Number(process.env.SENTRY_TRACES_SAMPLE_RATE ?? (isProd ? 0.05 : 0)),
      sendDefaultPii: false,
      maxValueLength: 2048,
      maxBreadcrumbs: 50,
      // Crash handling is ours; request bodies and locals never leave the host.
      integrations: (defaults) =>
        defaults.filter(
          (i) =>
            i.name !== "OnUncaughtException" &&
            i.name !== "OnUnhandledRejection" &&
            i.name !== "RequestData" &&
            i.name !== "LocalVariables",
        ),
      beforeSend: (event) => scrubEvent(event),
      beforeSendTransaction: (event) => scrubEvent(event),
      beforeBreadcrumb: (crumb) => scrubBreadcrumb(crumb),
      initialScope: { tags: { component } },
    });
    logger.startup(
      `🛰️  Sentry enabled (${component}, env=${process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || "development"})`,
    );
  } else if (isProd) {
    logger.warn(
      `🛰️  Sentry disabled in production (SENTRY_DSN unset) — set sentryDsn in the environment file (${component})`,
    );
  } else {
    logger.startup(`🛰️  Sentry disabled (no DSN) — crash handlers still active (${component})`);
  }

  registerSentrySink({
    breadcrumb: (level, message) => {
      if (!sentryOn) return;
      Sentry.addBreadcrumb({ category: "log", level, message: truncate(message) });
    },
    captureError: (err, message) => {
      if (!sentryOn) return;
      if (message) Sentry.addBreadcrumb({ category: "log", level: "error", message: truncate(message) });
      Sentry.captureException(err);
    },
    captureMessage: (message, level) => {
      if (!sentryOn) return;
      Sentry.captureMessage(truncate(message), level);
    },
  });

  installGlobalHandlers(component);
}

function truncate(s: string, n = 1000): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/** Flushes Sentry (bounded to 2 s, best effort) and then runs `after`. */
async function flushThen(after: () => void): Promise<void> {
  try {
    if (sentryOn) await Sentry.flush(2000);
  } catch {
    // Shutdown proceeds whether or not the flush succeeded.
  } finally {
    after();
  }
}

function installGlobalHandlers(component: Component): void {
  process.on("uncaughtException", (err, origin) => {
    logger.error(`💥 uncaughtException (${origin})`, err);
    Sentry.captureException(err, { tags: { fatal: "uncaughtException", origin } });
    void flushThen(() => process.exit(1));
  });

  process.on("unhandledRejection", (reason) => {
    logger.error("💥 unhandledRejection", reason);
    if (sentryOn) Sentry.captureException(reason, { tags: { fatal: "unhandledRejection" } });
  });

  process.on("warning", (w) => {
    logger.warn(`⚠️  process warning: ${w.name}: ${w.message}`);
    if (sentryOn) Sentry.captureMessage(`process warning: ${w.name}: ${w.message}`, "warning");
  });

  for (const sig of ["SIGTERM", "SIGINT"] as const) {
    process.on(sig, () => {
      logger.startup(`↩️  ${sig} received — flushing Sentry and exiting (${component})`);
      void flushThen(() => process.exit(0));
    });
  }
}

export { Sentry };
