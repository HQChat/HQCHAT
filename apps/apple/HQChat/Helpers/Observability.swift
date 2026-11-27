// HQChat (shared macOS + iOS)
//
// Crash reports, sent to Sentry only when the user has turned them on in
// Settings. Off by default: until then the SDK is never started, so no crash
// handler is installed and nothing is written or sent. When on, a report is
// the crash alone (stack, OS, device model, app version): no hangs, memory
// terminations, breadcrumbs, sessions or performance data.
//
// Wired from the app entry points (HQChatApp / HQChatIOSApp) via
// Observability.start(), and from Settings via Observability.setEnabled(_:).
//
// Build note: the Sentry SPM package (getsentry/sentry-cocoa, product "Sentry")
// is declared in the Xcode project for both app targets. This file is a shared
// source: it is in the macOS target automatically and added to the iOS target
// via the project's membership exceptions.

import Foundation
import Sentry

enum Observability {
    /// The user's choice, stored on this device only. Absent means off.
    static let enabledKey = "crashReportsEnabled"

    /// Send-only client DSN, embedded per deployment (see Deployment.sentryDSN);
    /// the Info.plist "SENTRY_DSN" key overrides it for one build.
    /// Empty = Sentry off, which is logged at startup rather than failing quietly.
    private static let defaultDSN = Deployment.sentryDSN

    private static var running = false

    /// Whether the user has turned crash reports on.
    static var isEnabled: Bool { UserDefaults.standard.bool(forKey: enabledKey) }

    /// Whether this build can send reports at all (a DSN is configured).
    static var isAvailable: Bool { !resolvedDSN().isEmpty }

    /// Call once at launch, before any app code runs, so a crash during startup
    /// is still captured. Starts Sentry only when the user opted in.
    static func start() {
        removeLegacyCaches()
        guard isEnabled else {
            Log.app.info("🛰️ crash reports off")
            return
        }
        startSDK()
    }

    /// The Settings toggle. Turning it off stops the SDK and deletes every
    /// report it had not sent yet.
    static func setEnabled(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: enabledKey)
        if on {
            startSDK()
        } else {
            if running {
                SentrySDK.close()
                running = false
            }
            removeCache()
            Log.app.info("🛰️ crash reports turned off; unsent reports deleted")
        }
    }

    private static func startSDK() {
        guard !running else { return }
        let dsn = resolvedDSN()
        guard !dsn.isEmpty else {
            Log.app.info("🛰️ crash reports on, but this build has no DSN")
            return
        }
        running = true

        SentrySDK.start { options in
            options.dsn = dsn
            options.environment = Self.environment()
            if let release = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String {
                options.releaseName = "hqchat@\(release)"
            }
            options.cacheDirectoryPath = cacheURL.path
            configureCrashOnly(options)
            configurePrivacy(options)
            configureReplay(options)
            #if DEBUG
            // Local debug builds send nothing unless asked to.
            options.enabled = ProcessInfo.processInfo.environment["SENTRY_ENABLE_DEBUG"] != nil
            options.debug = true
            #endif
        }

        SentrySDK.configureScope { scope in
            #if os(iOS)
            scope.setTag(value: "ios", key: "platform")
            #elseif os(macOS)
            scope.setTag(value: "macos", key: "platform")
            #endif
        }

        Log.app.info("🛰️ crash reports on (env=\(String(describing: Self.environment())))")
    }

    /// The crash handler and nothing else. Every other feature is set off
    /// explicitly so an SDK upgrade cannot flip a default: no hang or
    /// memory-termination reports, no release-health sessions (one per launch
    /// is a usage record), no client reports, no tracing.
    private static func configureCrashOnly(_ options: Options) {
        options.enableCrashHandler = true
        options.attachStacktrace = true
        options.enableAppHangTracking = false
        options.enableWatchdogTerminationTracking = false
        options.enableAutoSessionTracking = false
        options.sendClientReports = false
        options.tracesSampleRate = 0.0
        options.enableAutoPerformanceTracing = false
    }

    /// Every field that leaves the device is treated as world-readable: no IP,
    /// no screenshot or view hierarchy, no breadcrumbs, and every event scrubbed
    /// before sending.
    private static func configurePrivacy(_ options: Options) {
        options.sendDefaultPii = false
        #if os(iOS)
        options.attachScreenshot = false
        options.attachViewHierarchy = false
        #endif
        // Nothing about the app's own traffic: a URL names who is looked up
        // (`/users?username=`) or befriended, a failed request would make the
        // server able to trigger reports, and trace headers would go to every
        // host the app talks to.
        options.enableNetworkTracking = false
        options.enableNetworkBreadcrumbs = false
        options.enableCaptureFailedRequests = false
        options.tracePropagationTargets = []
        options.beforeSendSpan = { _ in nil }
        // No trail of what the user did before the crash.
        options.enableAutoBreadcrumbTracking = false
        options.maxBreadcrumbs = 0
        options.beforeBreadcrumb = { _ in nil }
        options.beforeSend = { event in Observability.scrub(event) }
    }

    /// No session replay: even masked, frames of a messenger's screens show
    /// who is in the list and when the user was in a conversation. Set
    /// explicitly, with the masks kept, so an SDK upgrade cannot flip it on.
    private static func configureReplay(_ options: Options) {
        #if os(iOS)
        options.sessionReplay.onErrorSampleRate = 0.0
        options.sessionReplay.sessionSampleRate = 0.0
        options.sessionReplay.maskAllText = true
        options.sessionReplay.maskAllImages = true
        #endif
    }

    // MARK: - Scrubbing (PII / secret redaction)
    //
    // The rules themselves live in Redaction.swift, which imports only
    // Foundation so a test slice and the differential fuzzer can compile them.
    // What stays here is the part that genuinely needs the SDK: mapping those
    // rules over a Sentry Event.

    /// Redact known-sensitive shapes from a single string.
    static func redact(_ input: String?) -> String? { Redaction.redact(input) }

    /// The context fields a crash report keeps; everything else the SDK
    /// gathers (boot time, free memory and disk, locale, screen) is dropped,
    /// since together they single out a device.
    private static let keptContext: [String: Set<String>] = [
        "os": ["name", "version", "build"],
        "device": ["family", "model", "arch", "simulator"],
        "app": ["app_version", "app_build"],
    ]

    /// Scrub a Sentry event before it leaves the device: drop network/topology
    /// identifiers and most of the device context, then redact message and
    /// exception strings.
    static func scrub(_ event: Event) -> Event {
        // Structural drops — never ship these. No user at all: the SDK fills
        // in a persistent installation id, which links every report from one
        // device.
        event.serverName = nil
        event.request = nil
        event.user = nil
        event.breadcrumbs = nil
        event.extra = nil
        if let context = event.context {
            var kept: [String: [String: Any]] = [:]
            for (name, fields) in context {
                guard let allowed = keptContext[name] else { continue }
                kept[name] = fields.filter { allowed.contains($0.key) }
            }
            event.context = kept
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
        return event
    }

    // MARK: - Report cache

    /// The SDK's own folder: unsent envelopes and the crash recorder's files
    /// both live under it, so deleting it removes every report not yet sent.
    private static var cacheURL: URL {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        return caches.appendingPathComponent("crash-reports", isDirectory: true)
    }

    private static func removeCache() {
        remove(cacheURL)
    }

    /// Before crash reports were opt-in, the SDK kept its files at the top of
    /// Caches. Anything left there was gathered without consent: delete it.
    private static func removeLegacyCaches() {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        for name in ["io.sentry", "SentryCrash"] {
            remove(caches.appendingPathComponent(name, isDirectory: true))
        }
    }

    private static func remove(_ url: URL) {
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        do {
            try FileManager.default.removeItem(at: url)
        } catch {
            Log.storage.error("🛰️ could not delete \(url.lastPathComponent, privacy: .public): \(String(describing: error))")
        }
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
