import Foundation

// Minimal assertion harness for the compiled Swift test executables.
// (We compile real app source files with these tests via swiftc — see run.sh —
//  so CI exercises the actual implementation, not a copy.)

var __failures = 0

func check(_ condition: Bool, _ message: String) {
    if condition {
        print("  ✓ \(message)")
    } else {
        print("  ✗ \(message)")
        __failures += 1
    }
}

/// Record a check that CANNOT run in this environment, as distinct from one that
/// ran and passed. Skips are counted and reported loudly at the end: a suite that
/// quietly stops covering something is worse than one that fails, because the
/// gate keeps going green while the guarantee stops being tested.
func skip(_ message: String, because reason: String) {
    print("  ⃠ SKIPPED \(message) — \(reason)")
    __skipped += 1
}

var __skipped = 0

/// How many skips this suite is expected to produce in this environment, set
/// per suite by `run.sh` from `tests/expected-skips.txt` (absent means zero).
/// A skip is a check that is not being tested, so more skips than expected
/// fails the run.
private var __expectedSkips: Int {
    Int(ProcessInfo.processInfo.environment["EXPECTED_SKIPS"] ?? "0") ?? 0
}

func finish() -> Never {
    let expected = __expectedSkips
    var censusFailed = false

    if __skipped > 0 {
        print("⚠️  \(__skipped) check(s) COULD NOT RUN here — see the reasons above.")
    }

    if __skipped > expected {
        // More skips than allowed: a check stopped running.
        print("""
        ❌ SKIP CENSUS: \(__skipped) skipped, but this suite is allowed \(expected).
           A check stopped running and the suite would otherwise still pass.
           Fix it, or — if the skip is genuinely unavoidable here — raise the
           count in apps/apple/tests/expected-skips.txt and say why in the file.
        """)
        censusFailed = true
    } else if __skipped < expected {
        // Fewer skips than expected is strictly better and happens legitimately
        // — a signed device build reaches the Enclave and the keychain. Not a
        // failure, but the census is now stale and should be tightened.
        print("""
        ℹ️  SKIP CENSUS: \(__skipped) skipped, \(expected) allowed — this
           environment covers more than the census assumes. Lower the count in
           apps/apple/tests/expected-skips.txt to hold on to the gain.
        """)
    }

    if __failures > 0 {
        print("❌ \(__failures) FAILED")
    } else if censusFailed {
        // Every assertion that RAN passed — saying "ALL PASS" here while exiting
        // non-zero is exactly the mixed signal this census exists to remove.
        print("❌ checks passed, but the skip census did not")
    } else {
        print("✅ ALL PASS")
    }
    exit(__failures == 0 && !censusFailed ? 0 : 1)
}
