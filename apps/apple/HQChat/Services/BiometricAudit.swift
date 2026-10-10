// Every Keychain call that could raise a biometric prompt, logged at the call
// site with who made it, when, and how long it took.
//
// Written because "how many prompts were there, and from where" was repeatedly
// unanswerable. Three separate counters each covered one store and missed the
// others, so a burst of prompts could leave a single line behind and the next
// guess was as good as the last.
//
// DURATION is the useful column. A Keychain operation that blocks on Face ID
// takes as long as a person takes — hundreds of milliseconds at least, usually
// more than a second. One that is satisfied from an authenticated context, or
// needs no user at all, returns in microseconds. So the log does not have to
// infer which call prompted: the elapsed time says it.

import Foundation

enum BiometricAudit {

    /// Anything slower than this had a human in the loop.
    private static let promptThreshold: TimeInterval = 0.25

    private static let lock = NSLock()
    private static var sequence = 0
    private static var prompts = 0

    private static let clock: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    /// Wrap a Security call. Logs the call site, the elapsed time, and whether
    /// that elapsed time means the user was asked.
    ///
    /// - Parameters:
    ///   - op: the Security function being called, e.g. `SecItemCopyMatching`.
    ///   - item: which protected thing, e.g. `profile-identity-key`.
    ///   - expectsPrompt: what the code BELIEVES. A mismatch with the measured
    ///     duration is the interesting case, and is flagged.
    @discardableResult
    static func measure<T>(_ op: String,
                           item: String,
                           expectsPrompt: Bool,
                           file: String = #fileID,
                           line: Int = #line,
                           function: String = #function,
                           _ body: () -> T) -> T {
        let seq = lock.withLock { sequence += 1; return sequence }

        let started = Date()
        let result = body()
        let elapsed = Date().timeIntervalSince(started)
        let prompted = elapsed >= promptThreshold

        if prompted {
            lock.lock(); prompts += 1; let total = prompts; lock.unlock()
            Log.keys.warning("""
            [bio #\(String(describing: seq)) \(String(describing: clock.string(from: started)))] 👁️ PROMPTED (\(String(describing: total)) so far) \
            \(String(describing: op)) \(String(describing: item)) — \(String(describing: Self.ms(elapsed))) \
            ← \(String(describing: file)):\(String(describing: line)) \(String(describing: function))\(String(describing: expectsPrompt ? "" : "  ⚠️ NOT EXPECTED TO PROMPT"))
            """)
        } else {
            Log.keys.warning("""
            [bio #\(String(describing: seq)) \(String(describing: clock.string(from: started)))] · silent \
            \(String(describing: op)) \(String(describing: item)) — \(String(describing: Self.ms(elapsed))) \
            ← \(String(describing: file)):\(String(describing: line)) \(String(describing: function))\(String(describing: expectsPrompt ? "  ⚠️ EXPECTED A PROMPT" : ""))
            """)
        }
        return result
    }

    /// The async variant, for `LAContext.evaluatePolicy`.
    @discardableResult
    static func measureAsync<T>(_ op: String,
                                item: String,
                                expectsPrompt: Bool,
                                file: String = #fileID,
                                line: Int = #line,
                                function: String = #function,
                                _ body: () async throws -> T) async rethrows -> T {
        let seq = lock.withLock { sequence += 1; return sequence }

        let started = Date()
        defer {
            let elapsed = Date().timeIntervalSince(started)
            let prompted = elapsed >= promptThreshold
            if prompted { lock.withLock { prompts += 1 } }
            Log.keys.info("""
            [bio #\(String(describing: seq)) \(String(describing: clock.string(from: started)))] \(String(describing: prompted ? "👁️ PROMPTED" : "· silent")) \
            \(String(describing: op)) \(String(describing: item)) — \(String(describing: Self.ms(elapsed))) \
            ← \(String(describing: file)):\(String(describing: line)) \(String(describing: function))
            """)
        }
        return try await body()
    }

    /// Total prompts observed, for a one-line summary.
    static var promptCount: Int {
        lock.lock(); defer { lock.unlock() }
        return prompts
    }

    static func summary() -> String {
        lock.lock(); defer { lock.unlock() }
        return "[bio] \(prompts) prompt(s) across \(sequence) protected Keychain call(s)"
    }

    private static func ms(_ t: TimeInterval) -> String {
        String(format: "%.1fms", t * 1000)
    }
}
