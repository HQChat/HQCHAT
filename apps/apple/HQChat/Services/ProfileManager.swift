import Foundation
import SwiftData
import Security
import LocalAuthentication

/// App-wide (NOT per-profile) authentication preferences, persisted in
/// UserDefaults so both the SwiftUI toggles and the non-UI ProfileManager read
/// the same source of truth.
enum AuthPrefs {
    /// When on, the decrypted identity key is held in memory for the
    /// foreground session (cleared on background and profile switch), so the
    /// handshake and later key reads do not each prompt. Off by default.
    static let unsecureKeyHoldKey = "unsecureKeyHoldEnabled"
    static var unsecureKeyHold: Bool {
        UserDefaults.standard.bool(forKey: unsecureKeyHoldKey)
    }
}

/// Which version of the end-user licence agreement this person accepted (App
/// Store Guideline 1.2 for user-generated content). App-wide, because it
/// records what a person agreed to, and kept across "reset all data".
enum EulaPrefs {
    /// The /eula revision date; bump when the agreement changes materially.
    static let currentVersion = "2026-09-13"
    static let acceptedVersionKey = "eula.acceptedVersion"

    /// The accepted version, as the create-profile sheet's `@AppStorage` stores it.
    static var acceptedVersion: String {
        UserDefaults.standard.string(forKey: acceptedVersionKey) ?? ""
    }
    static var isAccepted: Bool { acceptedVersion == currentVersion }
}

/// Profiles: creation, switching, deletion, and the identity key in the Keychain.
@MainActor
class ProfileManager: ObservableObject {
    @Published var currentProfile: Profile?
    @Published var profiles: [Profile] = []

    let modelContext: ModelContext
    private static let keychainServicePrefix = "app.hqchat.profile"

    /// Gated Keychain reads made, i.e. prompts shown. Diagnostics only.
    private static var promptCount = 0

    /// The current profile's decrypted secret key while a hold applies
    /// (session hold or an open unlock window).
    private var cachedSecretKey: Data?

    /// The gate the active profile's keys carry. Settled with the profile.
    private(set) var activeTier: KeyProtectionTier = .biometryCurrentSet

    init(modelContext: ModelContext) {
        self.modelContext = modelContext
        loadProfiles()
        loadActiveProfile()
    }

    /// Load all profiles from database
    func loadProfiles() {
        let descriptor = FetchDescriptor<Profile>(sortBy: [SortDescriptor(\.createdAt, order: .reverse)])
        profiles = (try? modelContext.fetch(descriptor)) ?? []
    }

    /// Load the active profile
    func loadActiveProfile() {
        let descriptor = FetchDescriptor<Profile>(
            predicate: #Predicate { $0.isActive == true }
        )
        currentProfile = try? modelContext.fetch(descriptor).first
        // The message-key unlock must satisfy this profile's key tier.
        MessageKeyStore.setActiveProfile(currentProfile?.id)
        activeTier = currentProfile.map { KeyProtectionTier.stored(for: $0.id.uuidString) }
            ?? .biometryCurrentSet
    }

    /// Whether one unlock covers the whole foreground session: the app-wide
    /// hold preference, or a tier-1 key (which a passcode opens every time anyway).
    private var holdsKeyForSession: Bool {
        AuthPrefs.unsecureKeyHold || activeTier.holdsKeyForSession
    }
    
    /// Creates an identity for `username`, optionally on another home server.
    /// - Parameter consentedTier: the protection tier the user explicitly agreed
    ///   to; required for the reduced tier, which is never reached by omission.
    /// - Throws: before any key material exists when the device cannot protect
    ///   a key at the requested tier.
    func createProfile(username: String, serverURL: String? = nil,
                       consentedTier: KeyProtectionTier? = nil) throws -> Profile {
        Log.keys.info("[ProfileManager] Creating profile: @\(String(describing: username))")
        let tier = try Self.protectionTier(consented: consentedTier)
        let (publicKey, secretKey) = try HQCService.generateKeypair(seed: try Self.randomSeed())

        // The seed is never persisted.
        let trimmedURL = serverURL?.trimmingCharacters(in: .whitespacesAndNewlines)
        let profile = Profile(username: username, publicKeyHex: publicKey.hexString,
                              serverURL: (trimmedURL?.isEmpty == false) ? trimmedURL : nil)
        modelContext.insert(profile)
        do {
            try storeSecretKey(secretKey, profileId: profile.id.uuidString, tier: tier)
        } catch {
            Log.keys.error("[ProfileManager] ❌ Failed to store secret key: \(String(describing: error))")
            modelContext.delete(profile)
            throw error
        }
        do {
            try modelContext.save()
        } catch {
            Log.keys.error("[ProfileManager] ❌ Failed to save profile: \(String(describing: error))")
            deleteSecretKey(profileId: profile.id.uuidString)
            throw error
        }
        loadProfiles()
        Log.keys.info("[ProfileManager] ✅ Profile created (\(String(describing: self.profiles.count)) total)")
        return profile
    }

    /// The tier a new key gets: the device sets the ceiling, the user may pick at
    /// or below it, and the reduced tier requires explicit consent. Checked
    /// before any key material exists, since the Keychain refuses an access
    /// control nothing on the device can satisfy.
    private static func protectionTier(consented: KeyProtectionTier?) throws -> KeyProtectionTier {
        let capability = DeviceAuthCapability.current
        guard let best = capability.tier else {
            Log.keys.error("[ProfileManager] ❌ device cannot protect a key: \(String(describing: capability))")
            throw ProfileError.deviceCannotProtectKey(capability)
        }
        let tier = consented ?? best
        // Never silently downgraded.
        guard tier.rawValue <= best.rawValue else { throw ProfileError.tierUnavailable(capability) }
        guard !tier.isReduced || consented == tier else { throw ProfileError.downgradeNotConsented(capability) }
        return tier
    }

    private static func randomSeed() throws -> Data {
        var seed = Data(count: HQCService.SEED_BYTES)
        let status = seed.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, HQCService.SEED_BYTES, bytes.baseAddress!)
        }
        guard status == errSecSuccess else {
            Log.keys.error("[ProfileManager] ❌ Failed to generate random seed: \(String(describing: status))")
            throw ProfileError.randomGenerationFailed
        }
        return seed
    }

    /// Switch to a different profile
    /// - Parameter skipBiometricVerification: If true, skip biometric verification (useful when profile was just created)
    func switchToProfile(_ profile: Profile, skipBiometricVerification: Bool = false) throws {
        if profile.id == currentProfile?.id && profile.isActive {
            return
        }

        // Nothing of the previous profile's keys may stay in memory.
        cachedSecretKey = nil
        MessageKeyStore.clearCache()
        MessageKeyGate.shared.lock()

        // Deactivate all profiles
        for p in profiles {
            p.isActive = false
        }

        // Activate selected profile
        profile.isActive = true
        currentProfile = profile
        
        // Save
        try modelContext.save()
        
        // Reload to ensure state is updated
        loadProfiles()
        loadActiveProfile()
        
        // Verify key access (prompts), opening the handshake window first so
        // the sign-in that follows reuses this unlock.
        if !skipBiometricVerification {
            beginHandshakeUnlock()
            guard verifyKeyAccess(reason: "profile switch") else {
                endHandshakeUnlock()
                // Roll the activation back, so selecting the profile again retries.
                profile.isActive = false
                currentProfile = nil
                try? modelContext.save()
                loadProfiles()
                loadActiveProfile()
                throw Self.readFailureReason(profileId: profile.id.uuidString)
            }
        }
    }

    /// Why a profile's key could not be read, comparing the tier it was written
    /// under with what the device can do now: temporarily locked, permanently
    /// destroyed (biometric enrolment changed, passcode removed), or an ordinary
    /// cancelled or failed unlock.
    static func readFailureReason(profileId: String) -> ProfileError {
        let tier = KeyProtectionTier.stored(for: profileId)
        let capability = DeviceAuthCapability.current
        switch (tier, capability) {
        case (_, .biometryLockout), (.biometryCurrentSet, .biometryDenied):
            // Recoverable: revoking the app's Face ID permission changes no enrolment.
            return .keyTemporarilyLocked(capability)
        case (.biometryCurrentSet, _) where capability.invalidatesBiometricKeys:
            return .keyDestroyedByEnrolmentChange
        case (.userPresence, .none):
            return .keyDestroyedByPasscodeRemoval
        default:
            return .keychainAccessFailed
        }
    }
    
    /// Deletes a profile and every key it owns: identity, message key, channel
    /// keys and published prekey secrets.
    func deleteProfile(_ profile: Profile) throws {
        // Drop any held key before removing the profile's Keychain items.
        cachedSecretKey = nil
        deleteSecretKey(profileId: profile.id.uuidString)
        MessageKeyStore.delete(for: profile.id)
        for friend in profile.friends ?? [] { friend.clearAESKeys() }
        PrekeyService.clear(profileID: profile.id)
        // Frames it never opened are not reachable from the profile row.
        let profileID: UUID? = profile.id
        let unopened = FetchDescriptor<PendingFrame>(predicate: #Predicate { $0.profileID == profileID })
        for frame in (try? modelContext.fetch(unopened)) ?? [] { modelContext.delete(frame) }
        
        // Delete from database (cascade will delete friends and messages)
        modelContext.delete(profile)
        
        // If this was the active profile, activate another one or clear
        if profile.isActive {
            if let firstProfile = profiles.first(where: { $0.id != profile.id }) {
                try switchToProfile(firstProfile)
            } else {
                currentProfile = nil
            }
        }
        
        // Save
        try modelContext.save()
        
        // Load updated list
        loadProfiles()
    }
    
    // MARK: - Biometric key access

    /// Whether the current profile has a stored identity key, asked without
    /// prompting (`UIFail`: a present item that needs a user answers
    /// `errSecInteractionNotAllowed`). Diagnostics only; never a gate.
    @discardableResult
    func hasStoredKey() -> Bool {
        guard let profileId = currentProfile?.id.uuidString else { return false }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "\(Self.keychainServicePrefix).\(profileId)",
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: LAContext.nonInteractive()
        ]
        var item: AnyObject?
        let status = BiometricAudit.measure("SecItemCopyMatching",
                                            item: "profile-identity-key EXISTS?",
                                            expectsPrompt: false) {
            SecItemCopyMatching(query as CFDictionary, &item)
        }
        if status != errSecSuccess && status != errSecInteractionNotAllowed {
            Log.keys.info("[ProfileManager] ℹ️ Key metadata lookup returned \(String(describing: status)) for profile \(String(describing: profileId))")
        }
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    // MARK: - Handshake unlock window

    /// How long an unlock window holds the key, covering the burst of key
    /// traffic that follows sign-in.
    private static let handshakeGrace: TimeInterval = 20

    private var handshakeUnlockUntil: Date?
    /// Drops the hold when the window expires.
    private var unlockCloseTask: Task<Void, Never>?

    /// True while the connection handshake may reuse a single unlock.
    private var handshakeWindowOpen: Bool {
        guard let until = handshakeUnlockUntil else { return false }
        return Date() < until
    }

    /// Opens the unlock window for an action of ours (sign-in, profile switch).
    func beginHandshakeUnlock() {
        openUnlockWindow()
    }

    /// Opens the window for inbound frames that need the private key, but
    /// never extends an open one: a peer must not be able to keep our key in
    /// memory by continuing to send.
    func beginKeyBurstUnlock() {
        guard !handshakeWindowOpen else { return }
        openUnlockWindow()
    }

    private func openUnlockWindow() {
        handshakeUnlockUntil = Date().addingTimeInterval(Self.handshakeGrace)
        unlockCloseTask?.cancel()
        unlockCloseTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(Self.handshakeGrace * 1_000_000_000))
            guard !Task.isCancelled else { return }
            self?.endHandshakeUnlock()
        }
    }

    /// Closes the window and drops the key unless a session hold applies.
    func endHandshakeUnlock() {
        unlockCloseTask?.cancel()
        unlockCloseTask = nil
        handshakeUnlockUntil = nil
        if !holdsKeyForSession { cachedSecretKey = nil }
    }

    /// Drops every in-memory key and authentication. Call on background,
    /// profile switch, or when the hold preference is turned off.
    func clearCachedKey() {
        unlockCloseTask?.cancel()
        unlockCloseTask = nil
        cachedSecretKey = nil
        handshakeUnlockUntil = nil
        MessageKeyStore.clearCache()
        MessageKeyGate.shared.lock()
    }

    /// The current profile's secret key. Under a session hold or an open
    /// unlock window it is read once and held; otherwise every call is a fresh,
    /// gated Keychain read.
    func getSecretKey(reason: String = "key read") -> Data? {
        guard let profileId = currentProfile?.id.uuidString else {
            return nil
        }
        if holdsKeyForSession || handshakeWindowOpen {
            if let cached = cachedSecretKey { return cached }
            let key = readSecretKey(profileId: profileId, reason: reason)
            cachedSecretKey = key
            return key
        }
        // No hold applies — make sure nothing lingers, then read fresh.
        cachedSecretKey = nil
        return readSecretKey(profileId: profileId, reason: reason)
    }

    /// Whether the current profile's key can be read (may prompt); primes any hold.
    func verifyKeyAccess(reason: String = "verify key access") -> Bool {
        guard currentProfile != nil else { return false }
        return getSecretKey(reason: reason) != nil
    }

    /// One gated Keychain read of a profile's secret key with a fresh `LAContext`
    /// (reused contexts caused rate-limit lockouts), or, on a once-per-session
    /// tier, with the context the message-key store already authenticated.
    /// - Parameter allowShared: false on the retry after a shared context failed.
    private func readSecretKey(profileId: String, reason: String = "key read",
                               allowShared: Bool = true) -> Data? {
        let keychainService = "\(Self.keychainServicePrefix).\(profileId)"

        // Sharing is only for tiers that hold; on tier 2 every read asks.
        let shared = (allowShared && activeTier.holdsKeyForSession)
            ? MessageKeyStore.sharedAuthenticatedContext() : nil

        // One line per prompt raised.
        if shared == nil {
            Self.promptCount += 1
            Log.keys.info("[ProfileManager] 🔐 auth prompt #\(String(describing: Self.promptCount)) — \(String(describing: reason))")
        }

        let context = shared ?? LAContext()
        context.localizedReason = "Access your private key"

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context
        ]

        var result: AnyObject?
        let status = BiometricCoordinator.withPrompt {
            BiometricAudit.measure("SecItemCopyMatching",
                                   item: "profile-identity-key \(profileId.prefix(8))…",
                                   expectsPrompt: true) {
                SecItemCopyMatching(query as CFDictionary, &result)
            }
        }
        guard status == errSecSuccess,
              let data = result as? Data else {
            if shared != nil {
                Log.keys.info("[ProfileManager] ↻ shared context did not open the key (\(String(describing: status))) — asking directly")
                MessageKeyStore.discardAuthenticatedContext()
                return readSecretKey(profileId: profileId, reason: reason, allowShared: false)
            }
            return nil
        }
        // Share the context so the message gate opens without another prompt.
        if activeTier.holdsKeyForSession, shared == nil {
            MessageKeyStore.adoptAuthenticatedContext(context)
        }
        return data
    }
    
    /// Stores a profile's secret key under the access control of `tier`, which
    /// the caller decided, and records the tier beside it.
    private func storeSecretKey(_ secretKey: Data, profileId: String,
                                tier: KeyProtectionTier) throws {
        let keychainService = "\(Self.keychainServicePrefix).\(profileId)"
        Log.keys.info("[ProfileManager] Storing key for service: \(String(describing: keychainService)) (tier \(String(describing: tier.rawValue)))")
        
        // Delete existing item if present
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService
        ]
        
        let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
        if deleteStatus == errSecSuccess {
            Log.keys.info("[ProfileManager] Deleted existing keychain item")
        } else if deleteStatus != errSecItemNotFound {
            Log.keys.warning("[ProfileManager] ⚠️ Warning: Failed to delete existing item: \(String(describing: deleteStatus))")
        }
        
        var error: Unmanaged<CFError>?
        
        // Tier 2 (`.biometryCurrentSet`) binds the key to the current biometric
        // enrolment; re-enrolling destroys it. Tier 1 (`.devicePasscode`) exists
        // for devices without biometrics. Access control is mandatory on every
        // platform; failing to create it throws.
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            tier.accessControlFlag,
            &error
        ) else {
            Log.keys.error("[ProfileManager] ❌ Could not create access control: \(String(describing: error?.takeRetainedValue().localizedDescription ?? "unknown"))")
            throw ProfileError.keychainStoreFailed(errSecParam)
        }

        // One literal: assigning an optional through a subscript could silently
        // drop the access control.
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecValueData as String: secretKey,
            kSecAttrAccessControl as String: accessControl
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            Log.keys.error("[ProfileManager] ❌ Failed to add keychain item: \(String(describing: status)) — \(String(describing: ProfileError.explain(status)))")
            KeyProtectionTier.deleteMarker(for: profileId)
            throw ProfileError.keychainStoreFailed(status)
        }

        // Written only after the key, so a marker always describes a real key.
        KeyProtectionTier.storeMarker(tier, for: profileId)
        
        Log.keys.info("[ProfileManager] ✅ Keychain item added — tier \(String(describing: tier.rawValue)), \(String(describing: tier.detail))")
    }
    
    /// Deletes a profile's secret key and its tier marker.
    private func deleteSecretKey(profileId: String) {
        let keychainService = "\(Self.keychainServicePrefix).\(profileId)"
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        KeyProtectionTier.deleteMarker(for: profileId)
    }
}

enum ProfileError: LocalizedError {
    case randomGenerationFailed
    case keychainStoreFailed(OSStatus)
    case keychainAccessFailed
    /// Nothing on this device can gate a key — no passcode, or biometrics are
    /// locked out. Raised BEFORE any key material is generated.
    case deviceCannotProtectKey(DeviceAuthCapability)
    /// A caller asked to create at the reduced tier without the user's consent.
    /// A programming error, surfaced rather than silently honoured.
    case downgradeNotConsented(DeviceAuthCapability)
    /// A caller asked for a STRONGER gate than the device can deliver. Refused
    /// rather than quietly satisfied with a weaker one.
    case tierUnavailable(DeviceAuthCapability)
    /// The key is intact; the device just will not authenticate right now.
    case keyTemporarilyLocked(DeviceAuthCapability)
    /// `.biometryCurrentSet` did what it promises. Terminal.
    case keyDestroyedByEnrolmentChange
    /// The passcode a tier-1 key was bound to is gone. Terminal.
    case keyDestroyedByPasscodeRemoval

    /// A sentence for a `SecItemAdd` status.
    static func explain(_ status: OSStatus) -> String {
        switch status {
        case errSecDuplicateItem:
            return "A key for this profile already exists."
        case errSecAuthFailed:
            return "This device could not authenticate you. Face ID, Touch ID, or a device passcode must be set up."
        case errSecInteractionNotAllowed:
            return "The device was locked. Unlock it and try again."
        case errSecMissingEntitlement:
            return "This build is missing the Keychain entitlement needed for biometric protection."
        default:
            return "The Keychain refused to store the key."
        }
    }

    var errorDescription: String? {
        switch self {
        case .randomGenerationFailed:
            return "Failed to generate random seed"
        case .keychainStoreFailed(let status):
            return "\(Self.explain(status)) (Keychain status \(status))"
        case .keychainAccessFailed:
            return "Failed to access private key. Biometric authentication may have been cancelled or failed."
        case .deviceCannotProtectKey(let capability):
            return "\(capability.headline) \(capability.remedy)"
        case .downgradeNotConsented(let capability):
            return "\(capability.headline) Reduced protection has to be confirmed before a profile can be created."
        case .tierUnavailable(let capability):
            return "\(capability.headline) \(capability.remedy)"
        case .keyTemporarilyLocked(let capability):
            return "\(capability.headline) \(capability.remedy)"
        case .keyDestroyedByEnrolmentChange:
            return "This profile's key was locked to the Face ID or Touch ID enrolment that existed when it was created, and that enrolment has changed. The key is permanently unreadable and the profile cannot be opened on this device."
        case .keyDestroyedByPasscodeRemoval:
            return "This profile's key was protected by the device passcode, and that passcode has been removed. The key is permanently unreadable."
        }
    }

    /// Whether trying again could work.
    var isRecoverable: Bool {
        switch self {
        case .keyDestroyedByEnrolmentChange, .keyDestroyedByPasscodeRemoval:
            return false
        default:
            return true
        }
    }
}

