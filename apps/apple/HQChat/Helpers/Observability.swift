// HQChat (shared macOS + iOS)
//
// Sentry crash reporting + a lightweight "coming crash" early-warning signal,
// mirroring what the relay server does. On Apple platforms the crash a user
// actually hits under stress is usually one of:
//   - an uncaught Swift error / signal (SIGABRT/SIGSEGV)      → Sentry crash handler
//   - a UI hang long enough for the watchdog to kill the app  → App Hang tracking
//   - the OS jetsam killing us for memory                     → watchdog-termination
//     tracking + our own memory-pressure breadcrumb/alert (the leading indicator,
//     analogous to the server's rss/event-loop early warning).
//
// Wired from the app entry points (HQChatApp / HQChatIOSApp) via
// Observability.start(). Safe to call more than once.
//
// Build note: the Sentry SPM package (getsentry/sentry-cocoa, product "Sentry")
// is declared in the Xcode project for both app targets. This file is a shared
// source: it is in the macOS target automatically and added to the iOS target
// via the project's membership exceptions.

import Foundation
import Sentry

enum Observability {
    /// Send-only client DSN, embedded per deployment (see Deployment.sentryDSN);
    /// the Info.plist "SENTRY_DSN" key overrides it for one build.
    /// Empty = Sentry off, which is logged at startup rather than failing quietly.
    private static let defaultDSN = Deployment.sentryDSN

    private static var started = false
    private static var memoryPressureSource: DispatchSourceMemoryPressure?

    /// Report a non-fatal failure that has no sensible UI to show it in — a
    /// local persistence error, say. Use instead of `try?`, which drops the
    /// error entirely, or `dlog`, which compiles out in Release.
    static func capture(_ error: Error, context: String) {
        Log.app.warning("[\(String(describing: context))] ⚠️ \(String(describing: error))")
        guard started else { return }
        SentrySDK.capture(error: error) { scope in
            scope.setTag(value: context, key: "context")
        }
    }

    /// Starts Sentry when a DSN is configured; a no-op otherwise or when already started.
    static func start() {
        guard !started else { return }
        started = true

        let dsn = resolvedDSN()
        guard !dsn.isEmpty else {
            Log.app.info("🛰️ Sentry disabled (no DSN)")
            return
        }

        SentrySDK.start { options in
            options.dsn = dsn
            options.environment = Self.environment()
            if let release = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String {
                options.releaseName = "hqchat@\(release)"
            }
            configureStability(options)
            configurePrivacy(options)
            configureReplay(options)
            #if DEBUG
            // Local debug builds send nothing unless asked to.
            options.enabled = ProcessInfo.processInfo.environment["SENTRY_ENABLE_DEBUG"] != nil
            #endif
        }

        SentrySDK.configureScope { scope in
            #if os(iOS)
            scope.setTag(value: "ios", key: "platform")
            #elseif os(macOS)
            scope.setTag(value: "macos", key: "platform")
            #endif
        }

        startMemoryPressureWatch()
        Log.app.info("🛰️ Sentry enabled (env=\(String(describing: Self.environment())))")
    }

    /// Crashes, hangs reported before a watchdog kill, memory terminations
    /// reconstructed on the next launch, and light performance sampling.
    private static func configureStability(_ options: Options) {
        options.enableCrashHandler = true
        options.attachStacktrace = true
        options.enableAppHangTracking = true
        options.appHangTimeoutInterval = 2.0
        options.enableWatchdogTerminationTracking = true
        #if DEBUG
        options.tracesSampleRate = 0.0
        options.debug = true
        #else
        options.tracesSampleRate = 0.1
        #endif
    }

    /// Every field that leaves the device is treated as world-readable: no IP,
    /// no screenshot or view hierarchy, bounded breadcrumbs, and every event and
    /// breadcrumb scrubbed before sending. Set explicitly so an SDK upgrade cannot
    /// flip a default.
    private static func configurePrivacy(_ options: Options) {
        options.sendDefaultPii = false
        #if os(iOS)
        options.attachScreenshot = false
        options.attachViewHierarchy = false
        #endif
        options.maxBreadcrumbs = 50
        options.beforeSend = { event in Observability.scrub(event) }
        options.beforeBreadcrumb = { crumb in Observability.scrub(crumb) }
    }

    /// iOS only: a replay of the last ~30 s of UI for each error, never for
    /// ordinary sessions, with every text node and image masked.
    private static func configureReplay(_ options: Options) {
        #if os(iOS)
        options.sessionReplay.onErrorSampleRate = 1.0
        options.sessionReplay.sessionSampleRate = 0.0
        options.sessionReplay.maskAllText = true
        options.sessionReplay.maskAllImages = true
        #endif
    }

    // MARK: - Coming-crash early warning (memory pressure)

    /// Watch OS memory-pressure notifications. warning → breadcrumb; critical →
    /// a Sentry warning event, so you get an alert BEFORE jetsam kills the app —
    /// the client-side analogue of the server's rss/event-loop early warning.
    private static func startMemoryPressureWatch() {
        let source = DispatchSource.makeMemoryPressureSource(
            eventMask: [.warning, .critical],
            queue: .global(qos: .utility)
        )
        source.setEventHandler {
            let event = source.data
            if event.contains(.critical) {
                SentrySDK.addBreadcrumb(Self.crumb("memory pressure: critical", level: .error))
                SentrySDK.capture(message: "[early-warning] memory pressure CRITICAL — jetsam risk") { scope in
                    scope.setLevel(.warning)
                }
            } else if event.contains(.warning) {
                SentrySDK.addBreadcrumb(Self.crumb("memory pressure: warning", level: .warning))
            }
        }
        source.resume()
        memoryPressureSource = source
    }

    private static func crumb(_ message: String, level: SentryLevel) -> Breadcrumb {
        let b = Breadcrumb()
        b.level = level
        b.category = "device.memory"
        b.message = message
        return b
    }

    // MARK: - Scrubbing (PII / secret redaction)
    //
    // The rules themselves live in Redaction.swift, which imports only
    // Foundation so a test slice and the differential fuzzer can compile them.
    // What stays here is the part that genuinely needs the SDK: mapping those
    // rules over a Sentry Event and Breadcrumb.

    /// Redact known-sensitive shapes from a single string.
    static func redact(_ input: String?) -> String? { Redaction.redact(input) }

    /// Deep-scrub an arbitrary bag: redact strings, drop sensitive-named keys.
    private static func scrubDeep(_ value: Any) -> Any { Redaction.scrubDeep(value) }

    /// Scrub a Sentry event before it leaves the device: drop network/topology
    /// identifiers, then redact message + exception strings + breadcrumbs + bags.
    static func scrub(_ event: Event) -> Event {
        // Structural drops — never ship these.
        event.serverName = nil
        event.request = nil
        if let user = event.user {
            user.ipAddress = nil
            user.email = nil
            user.username = nil
            event.user = user
        }
        // Message. `formatted` is read-only on SentryMessage, so rebuild it.
        if let m = event.message {
            let nm = SentryMessage(formatted: redact(m.formatted) ?? m.formatted)
            nm.message = redact(m.message)
            nm.params = nil // template params can carry raw values; drop them
            event.message = nm
        }
        // Exceptions.
        if let exceptions = event.exceptions {
            for ex in exceptions { ex.value = redact(ex.value) ?? ex.value }
        }
        // Breadcrumbs carried on the event.
        if let crumbs = event.breadcrumbs {
            for c in crumbs { _ = scrub(c) }
        }
        // Structured bags.
        if let extra = event.extra {
            event.extra = scrubDeep(extra) as? [String: Any]
        }
        return event
    }

    /// Scrub a single breadcrumb (message + data bag).
    static func scrub(_ crumb: Breadcrumb) -> Breadcrumb {
        crumb.message = redact(crumb.message)
        if let data = crumb.data, let scrubbed = scrubDeep(data) as? [String: Any] {
            for key in data.keys { crumb.setData(value: scrubbed[key], key: key) }
        }
        return crumb
    }

    // MARK: - Helpers

    private static func resolvedDSN() -> String {
        if let override = Bundle.main.infoDictionary?["SENTRY_DSN"] as? String {
            return override.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return defaultDSN
    }

    private static func environment() -> String {
        if let env = Bundle.main.infoDictionary?["SENTRY_ENVIRONMENT"] as? String, !env.isEmpty {
            return env
        }
        #if DEBUG
        return "development"
        #else
        return "production"
        #endif
    }
}
