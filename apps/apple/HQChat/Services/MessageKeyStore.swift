// The profile's Secure Enclave key, which the core's vault uses
// (SecureEnclaveVault): its public half seals with no user present (a message
// arriving in the background), one ECDH with the private half opens and needs
// the user, gated by the profile's protection tier.
//
// One authenticated `LAContext` (the unlock) is reused for every operation of
// the session, so it costs one prompt. Deleting a profile deletes its key
// pair, which makes everything sealed to it permanently unreadable.

import Foundation
import CryptoKit
import LocalAuthentication
#if canImport(UIKit)
import UIKit
#endif

enum MessageKeyStore {
    /// Distinct from `AESKeyStore`'s service so a profile wipe can drop message
    /// keys without touching per-friend channel keys.
    static let service = "app.hqchat.messagekeys"

    private static let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM

    private static func tag(_ profileID: UUID) -> Data {
        Data("app.hqchat.messagekey.\(profileID.uuidString)".utf8)
    }

    /// Public keys carry no authority; caching them keeps sealing off the Keychain.
    private static var publicCache: [UUID: SecKey] = [:]
    private static let lock = NSLock()

    /// The context one successful `evaluatePolicy` produced. Reads use it and
    /// never authenticate themselves: `Message.content` is read from view
    /// bodies and must never raise a prompt, so while this is nil reads return nil.
    private static var readContext: LAContext?

    /// The profile whose key tier the read unlock must satisfy. Set by
    /// `ProfileManager` when the active profile is settled; nil reads as the
    /// strong tier.
    private static var activeProfileID: UUID?

    static func setActiveProfile(_ id: UUID?) {
        lock.lock(); defer { lock.unlock() }
        activeProfileID = id
    }

    /// The tier the active profile's keys carry, for a store that writes items
    /// the same unlock must open (`AESKeyStore`).
    static var currentTier: KeyProtectionTier { activeTier }

    /// The tier the current unlock must authenticate against.
    private static var activeTier: KeyProtectionTier {
        lock.lock()
        let id = activeProfileID
        lock.unlock()
        guard let id else { return .biometryCurrentSet }
        return KeyProtectionTier.stored(for: id.uuidString)
    }

    /// The session's authenticated context, for a tier that unlocks once per
    /// session; both of a profile's keys share the tier, so one context opens both.
    static func sharedAuthenticatedContext() -> LAContext? {
        lock.lock(); defer { lock.unlock() }
        return lockedOut ? nil : readContext
    }

    /// Adopts a context that already satisfied the user, avoiding a second prompt.
    static func adoptAuthenticatedContext(_ context: LAContext) {
        lock.lock()
        let fresh = readContext == nil && !lockedOut
        if fresh {
            readContext = context
            promptWindows += 1
        }
        let window = promptWindows
        lock.unlock()
        if fresh {
            Log.keys.info("[MessageKeyStore] 🔓 read unlocked by the identity-key unlock (window #\(String(describing: window)))")
        }
    }

    /// Drops a shared context that did not open a key, so the caller authenticates itself.
    static func discardAuthenticatedContext() {
        lock.lock(); defer { lock.unlock() }
        readContext?.invalidate()
        readContext = nil
    }

    /// Whether a synchronous read can succeed right now.
    static var canRead: Bool {
        lock.lock(); defer { lock.unlock() }
        return readContext != nil && !lockedOut
    }

    /// What one unlock attempt settled.
    enum UnlockOutcome {
        /// Authenticated; synchronous reads will now succeed.
        case granted
        /// The user said no. Stop asking until something changes.
        case refused
        /// The system took the hardware (usually a concurrent prompt). Ask again.
        case interrupted
    }

    /// Authenticates once so a whole screen of rows opens without a prompt
    /// each. Call before showing message bodies; safe to call again.
    static func authenticateForReading(reason: String) async -> UnlockOutcome {
        if canRead { return .granted }
        // No profile means no message keys and nothing to unlock.
        guard activeProfileID != nil else { return .refused }

        let tier = activeTier

        // On a tier that unlocks once per session, let a sign-in already in
        // flight publish its context instead of raising a second sheet beside it.
        if tier.holdsKeyForSession {
            let deadline = Date().addingTimeInterval(Self.waitForSharedUnlock)
            while !canRead, Date() < deadline {
                if BiometricCoordinator.isBusy || Self.sharedAuthenticatedContext() == nil {
                    do { try await Task.sleep(nanoseconds: 200_000_000) } catch { return .interrupted }
                } else {
                    break
                }
            }
            if canRead { return .granted }
        }

        BiometricCoordinator.begin()
        defer { BiometricCoordinator.end() }

        let context = LAContext()
        // Each row's unwrap would otherwise re-authenticate. The context is
        // invalidated by `clearCache()` on background and profile switch.
        context.touchIDAuthenticationAllowableReuseDuration =
            LATouchIDAuthenticationMaximumAllowableReuseDuration
        do {
            let ok = try await BiometricAudit.measureAsync("LAContext.evaluatePolicy",
                                                           item: "message-read unlock",
                                                           expectsPrompt: true) {
                // nosemgrep: swift.biometrics-and-auth.local-biometrics.insecure-biometrics
                // The boolean grants nothing: access comes from the Keychain
                // checking this context against the key's ACL. The policy is the
                // one the key's recorded tier requires.
                try await context.evaluatePolicy(tier.policy, localizedReason: reason)
            }
            guard ok else { return .refused }
            lock.withLock {
                readContext = context
                lockedOut = false
                promptWindows += 1
            }
            Log.keys.info("[MessageKeyStore] 🔓 read unlocked (window #\(String(describing: promptWindows)))")
            return .granted
        } catch let error as LAError {
            let outcome: UnlockOutcome
            switch error.code {
            case .userCancel, .userFallback, .authenticationFailed,
                 .biometryLockout, .passcodeNotSet, .biometryNotEnrolled:
                outcome = .refused
            default:
                outcome = .interrupted
            }
            Log.keys.info("[MessageKeyStore] 🔒 unlock \(String(describing: outcome)) — \(String(describing: error.localizedDescription))")
            return outcome
        } catch {
            Log.keys.info("[MessageKeyStore] 🔒 unlock interrupted — \(String(describing: error.localizedDescription))")
            return .interrupted
        }
    }

    /// How long a once-per-session tier waits for a sign-in's context before asking itself.
    private static let waitForSharedUnlock: TimeInterval = 6

    /// Set when the OS refuses further authentication attempts (it rate-limits
    /// them, and every further attempt counts). While set, `unwrap` returns nil
    /// without touching the Keychain; `clearCache()` resets it.
    private static var lockedOut = false

    /// So an ACL refusal is reported once, not once per row.
    private static var aclRefusalAnnounced = false

    /// True when reads stopped because the OS refused; callers must not treat a
    /// row as permanently unreadable in that state.
    static var isLockedOut: Bool {
        lock.lock(); defer { lock.unlock() }
        return lockedOut
    }

    /// Authentication windows opened, i.e. roughly the prompts this store cost. Diagnostics only.
    private static var promptWindows = 0

    // MARK: - Sealing (no authentication)

    /// This profile's public key, creating the key pair on first use.
    static func publicKey(for profileID: UUID) -> SecKey? {
        lock.lock()
        defer { lock.unlock() }
        if let cached = publicCache[profileID] { return cached }
        if let stored = loadStoredPublicKey(profileID) {
            publicCache[profileID] = stored
            return stored
        }
        guard let priv = createKeyPair(profileID), let pub = SecKeyCopyPublicKey(priv) else { return nil }
        publicCache[profileID] = pub
        return pub
    }

    /// `SecKeyCreateDecryptedData` refusing the operation itself (LocalAuthentication domain).
    private static let aclOperationNotAllowed = -1009

    /// Keychain account holding the public half, readable without authentication
    /// so sealing never prompts.
    private static func publicAccount(_ profileID: UUID) -> String { "pub.\(profileID.uuidString)" }

    private static func storePublicKey(_ pub: SecKey, for profileID: UUID) {
        guard let data = SecKeyCopyExternalRepresentation(pub, nil) as Data? else { return }
        writeItem(data, account: publicAccount(profileID))
    }

    private static func loadStoredPublicKey(_ profileID: UUID) -> SecKey? {
        guard let data = readItem(publicAccount(profileID)) else { return nil }
        return SecKeyCreateWithData(data as CFData, [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ] as CFDictionary, nil)
    }

    // MARK: - Opening (requires the user)

    /// Unwraps a 3.1.1 per-message key with `context`, or with the read
    /// context from `authenticateForReading`; nil (never a prompt) when
    /// neither is available. TRANSITION: only the move to the core
    /// (`Migration/`) opens 3.1.1 messages, and this goes with it.
    static func unwrap(_ wrapped: Data, for profileID: UUID, context: LAContext? = nil) -> SymmetricKey? {
        if isLockedOut { return nil }
        lock.lock()
        let auth = context ?? readContext
        lock.unlock()
        guard let auth else { return nil }

        guard let priv = privateKeyRef(profileID, context: auth) else { return nil }
        var error: Unmanaged<CFError>?
        let raw = BiometricAudit.measure("SecKeyCreateDecryptedData",
                                         item: "message-key (per row)",
                                         expectsPrompt: false) {
            SecKeyCreateDecryptedData(priv, algorithm, wrapped as CFData, &error) as Data?
        }
        if raw == nil {
            let cfError = error?.takeRetainedValue()
            let code = cfError.map { CFErrorGetCode($0) }
            let domain = cfError.map { CFErrorGetDomain($0) as String } ?? ""
            switch code ?? 0 {
            case aclOperationNotAllowed where domain == "com.apple.LocalAuthentication":
                // Structural: the key's ACL forbids the operation, so no retry helps.
                lock.lock()
                let announced = aclRefusalAnnounced
                aclRefusalAnnounced = true
                lock.unlock()
                if !announced {
                    Log.keys.error("[MessageKeyStore] ❌ the Secure Enclave refused a private-key operation; the authentication context was not accepted")
                }
            case Int(errSecAuthFailed), Int(errSecInteractionNotAllowed), Int(errSecUserCanceled):
                // Only an authentication refusal latches: retrying it makes the lockout worse.
                lock.lock()
                lockedOut = true
                promptWindows += 1
                lock.unlock()
                Log.keys.info("[MessageKeyStore] 🔒 authentication refused (code \(String(describing: code.map(String.init) ?? "?"))) — not retrying until the next unlock")
            default:
                // A wrong or corrupt envelope affects this row only.
                Log.keys.warning("[MessageKeyStore] ⚠️ could not unwrap one message key (domain \(String(describing: domain)), code \(String(describing: code.map(String.init) ?? "?"))) — this row only")
            }
            return nil
        }
        guard let raw, raw.count == 32 else { return nil }
        lock.lock()
        keyUnwraps += 1
        let total = keyUnwraps
        lock.unlock()
        if total == 1 || total % 10 == 0 {
            Log.keys.info("[MessageKeyStore] 🔑 message keys unwrapped: \(String(describing: total)) (auth windows: \(String(describing: promptWindows)))")
        }
        return SymmetricKey(data: raw)
    }

    /// Per-row unwraps run; compared with `promptWindows` it shows whether the
    /// reuse window covers them.
    private static var keyUnwraps = 0

    // MARK: - Lifecycle

    /// Whether this profile has a key pair, without minting one or prompting.
    static func hasKey(for profileID: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if publicCache[profileID] != nil { return true }
        if loadStoredPublicKey(profileID) != nil { return true }
        // Without interaction, a present item that needs a user answers
        // `errSecInteractionNotAllowed` instead of prompting.
        let probe: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrApplicationTag as String: tag(profileID),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: false,
            kSecUseAuthenticationContext as String: LAContext.nonInteractive()
        ]
        let status = BiometricAudit.measure("SecItemCopyMatching",
                                            item: "message-key PAIR EXISTS?",
                                            expectsPrompt: false) {
            SecItemCopyMatching(probe as CFDictionary, nil)
        }
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// Deletes the profile's key pair and stored public key. Call when the profile is deleted.
    static func delete(for profileID: UUID) {
        lock.lock()
        defer { lock.unlock() }
        publicCache[profileID] = nil
        SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrApplicationTag as String: tag(profileID)
        ] as CFDictionary)
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: service,
            kSecAttrAccount as String: publicAccount(profileID)
        ] as CFDictionary)
    }

    /// Forgets in-memory keys and the authentication (Keychain items survive).
    /// Called on background and profile switch.
    static func clearCache() {
        lock.lock()
        defer { lock.unlock() }
        publicCache.removeAll()
        lockedOut = false
        readContext?.invalidate()
        readContext = nil
    }

    // MARK: - Keychain

    /// The private key reference, fetched through `context` or the read context;
    /// without either the query fails rather than prompting.
    private static func privateKeyRef(_ profileID: UUID, context: LAContext?) -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrApplicationTag as String: tag(profileID),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        if let context = context ?? readContext {
            query[kSecUseAuthenticationContext as String] = context
        } else {
            query[kSecUseAuthenticationContext as String] = LAContext.nonInteractive()
        }
        var result: AnyObject?
        let status = BiometricAudit.measure("SecItemCopyMatching",
                                            item: "message-key REF",
                                            expectsPrompt: false) {
            SecItemCopyMatching(query as CFDictionary, &result)
        }
        guard status == errSecSuccess, let result, CFGetTypeID(result) == SecKeyGetTypeID() else { return nil }
        return (result as! SecKey)
    }

    /// Creates the profile's P-256 key pair inside the Secure Enclave and stores
    /// its public half. Fails where there is no Enclave (the Simulator, an
    /// unsigned macOS binary); there is deliberately no fallback.
    private static func createKeyPair(_ profileID: UUID) -> SecKey? {
        // The same tier as the identity key, so both of a profile's keys open
        // together. `.biometryCurrentSet` tiers make history unreadable after a
        // biometric re-enrolment; tiers are never OR'd with a passcode fallback.
        // `.privateKeyUsage` is required: without it the Enclave refuses the
        // ECIES unwrap (LocalAuthentication -1009).
        let tier = KeyProtectionTier.stored(for: profileID.uuidString)
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, tier.accessControlFlag], nil
        ) else { return nil }

        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            // Enclave keys can only live in the data protection keychain, which
            // macOS does not use by default.
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag(profileID),
                kSecAttrAccessControl as String: access
            ]
        ]
        var error: Unmanaged<CFError>?
        let created = BiometricAudit.measure("SecKeyCreateRandomKey",
                                             item: "message-key PAIR (create)",
                                             expectsPrompt: false) {
            SecKeyCreateRandomKey(attrs as CFDictionary, &error)
        }
        if created == nil {
            let code = (error?.takeRetainedValue()).map { CFErrorGetCode($0) } ?? 0
            let meaning: String
            switch code {
            case -34018:
                meaning = "errSecMissingEntitlement — the app is signed without an application "
                    + "identifier or keychain access group, so the data protection keychain is closed to it"
            case -25293: meaning = "errSecAuthFailed — no Enclave here (Simulator)"
            case -25308: meaning = "errSecInteractionNotAllowed — unsigned binary"
            default:     meaning = "see the Security framework error above"
            }
            Log.keys.error("[MessageKeyStore] ❌ could not create the Enclave key pair (\(String(describing: code))): \(String(describing: meaning))")
        }
        if let created, let pub = SecKeyCopyPublicKey(created) {
            storePublicKey(pub, for: profileID)
        }
        return created
    }

    private static func writeItem(_ data: Data, account: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ] as CFDictionary)
        SecItemAdd([
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            // Readable after first unlock so a push-woken background seal works.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ] as CFDictionary, nil)
    }

    private static func readItem(_ account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = BiometricAudit.measure("SecItemCopyMatching",
                                            item: "message-key store item",
                                            expectsPrompt: false) {
            SecItemCopyMatching(query as CFDictionary, &result)
        }
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }
}

/// Drives the single read-unlock prompt and tells SwiftUI when it happened.
///
/// `Message.content` is synchronous and cannot authenticate; `evaluatePolicy`
/// is async and must not run from a view body. Message surfaces call `unlock`
/// when they appear, rows render as locked until it resolves, and `isUnlocked`
/// re-renders them. The unlock lasts until background or profile switch
/// (`MessageKeyStore.clearCache()`).
@MainActor
final class MessageKeyGate: ObservableObject {
    static let shared = MessageKeyGate()

    @Published private(set) var isUnlocked = false
    /// Set once the user declined, so appearing views stop asking; `unlock(retry: true)` clears it.
    @Published private(set) var wasDeclined = false
    /// The attempt in progress; concurrent callers wait for it.
    private var current: Task<Void, Never>?

    private init() {}

    /// Asks once; concurrent callers share the prompt and return when it
    /// settles. An interrupted attempt (a colliding prompt) is retried with
    /// backoff; only the user's refusal stops it.
    func unlock(reason: String = "Read your messages", retry: Bool = false) async {
        if retry { wasDeclined = false }
        if let current { return await current.value }
        guard !isUnlocked, !wasDeclined else { return }
        let attempt = Task { await self.attempt(reason: reason) }
        current = attempt
        await attempt.value
        current = nil
    }

    private func attempt(reason: String) async {

        for attempt in 0..<Self.maxInterruptedRetries {
            // SwiftUI cancels a `.task` when its view rebuilds; stop asking then.
            if Task.isCancelled { return }
            guard await Self.waitUntilAppIsActive(timeout: Self.waitForActive),
                  !Task.isCancelled else { return }
            // Never raise a prompt beside one already on screen.
            guard await BiometricCoordinator.waitUntilFree(timeout: Self.waitForOtherPrompt),
                  !Task.isCancelled else { return }

            if attempt > 0 {
                // A cancelled sleep throws; returning (not `try?`) ends the backoff.
                let delay = Self.retryBaseNanoseconds << UInt64(attempt - 1)
                do { try await Task.sleep(nanoseconds: min(delay, Self.retryCapNanoseconds)) }
                catch { return }
            }
            switch await MessageKeyStore.authenticateForReading(reason: reason) {
            case .granted:
                isUnlocked = true
                wasDeclined = false
                return
            case .refused:
                isUnlocked = false
                wasDeclined = true
                return
            case .interrupted:
                continue
            }
        }
        // Still interrupted: the next screen or foreground asks again.
        isUnlocked = false
    }

    /// Whether the app is active, waiting up to `timeout`: LocalAuthentication
    /// shows no UI for an inactive app (`LAError.notInteractive`).
    private static func waitUntilAppIsActive(timeout: TimeInterval) async -> Bool {
        #if canImport(UIKit)
        let deadline = Date().addingTimeInterval(timeout)
        while UIApplication.shared.applicationState != .active {
            if Date() >= deadline { return false }
            do { try await Task.sleep(nanoseconds: 150_000_000) } catch { return false }
        }
        #endif
        return true
    }

    /// 1s, 2s, 4s, 8s, 8s… ≈ 30s before giving up on a device that cannot authenticate.
    private static let maxInterruptedRetries = 6
    private static let retryBaseNanoseconds: UInt64 = 1_000_000_000
    private static let retryCapNanoseconds: UInt64 = 8_000_000_000
    /// How long to stand aside for a prompt already on screen.
    private static let waitForOtherPrompt: TimeInterval = 30
    /// How long to wait for the scene to become active.
    private static let waitForActive: TimeInterval = 15

    /// Locks the UI along with the store's caches.
    func lock() {
        isUnlocked = false
        wasDeclined = false
    }
}

extension LAContext {
    /// A context that never prompts: an item that needs the user answers
    /// `errSecInteractionNotAllowed` instead.
    static func nonInteractive() -> LAContext {
        let context = LAContext()
        context.interactionNotAllowed = true
        return context
    }
}

// MARK: - The core's device key

/// What the core's `KeyVault` needs from the profile's Enclave key: its public
/// half, which seals without the user, and one ECDH, which opens. The same key
/// that wraps message keys today, with the same tier and the same session
/// context, so moving to the core adds no key and no prompt.
extension MessageKeyStore {
    enum AgreementError: Error, Equatable {
        /// No authenticated context: the user has not unlocked this session.
        case locked
        /// The profile has no Enclave key.
        case missing
        /// The Enclave refused (a key from another device, a bad point, …).
        case refused(Int)
    }

    /// The device key's public half, X9.63 uncompressed (65 bytes), creating
    /// the pair on first use. Never prompts.
    static func devicePublicKey(for profileID: UUID) -> Data? {
        guard let pub = publicKey(for: profileID) else { return nil }
        return SecKeyCopyExternalRepresentation(pub, nil) as Data?
    }

    /// One ECDH between the device key and `ephemeralPublic` (X9.63), under the
    /// session's authenticated context. Never prompts: without that context it
    /// throws `.locked`, and the core asks the app for the unlock.
    static func agree(ephemeralPublic: Data, for profileID: UUID) throws -> Data {
        if isLockedOut { throw AgreementError.locked }
        guard let context = sharedAuthenticatedContext() else { throw AgreementError.locked }
        guard let priv = privateKeyRef(profileID, context: context) else {
            throw hasKey(for: profileID) ? AgreementError.locked : AgreementError.missing
        }
        guard let peer = SecKeyCreateWithData(ephemeralPublic as CFData, [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ] as CFDictionary, nil) else { throw AgreementError.refused(Int(errSecParam)) }
        var error: Unmanaged<CFError>?
        let shared = BiometricAudit.measure("SecKeyCopyKeyExchangeResult",
                                            item: "device key (core)",
                                            expectsPrompt: false) {
            SecKeyCopyKeyExchangeResult(priv, .ecdhKeyExchangeStandard, peer, [:] as CFDictionary, &error) as Data?
        }
        guard let shared else {
            let code = (error?.takeRetainedValue()).map { CFErrorGetCode($0) } ?? 0
            throw code == aclOperationNotAllowed ? AgreementError.locked : AgreementError.refused(code)
        }
        return shared
    }
}
