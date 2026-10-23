import Foundation
import SwiftData
import Security
import LocalAuthentication

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

/// Profiles: creation, switching and deletion. A profile's identity lives in
/// its core store (`ChatStore`), sealed to its Secure Enclave key; this keeps
/// the list, the protection tier each key was made with, and the cleanup.
@MainActor
class ProfileManager: ObservableObject {
    @Published var currentProfile: Profile?
    @Published var profiles: [Profile] = []

    let modelContext: ModelContext

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
        // The unlock must satisfy this profile's key tier.
        MessageKeyStore.setActiveProfile(currentProfile?.id)
    }

    /// Creates a profile for `username`, optionally on another home server.
    /// Its identity is made by the core when the profile opens (`AppState`).
    /// - Parameter consentedTier: the protection tier the user explicitly agreed
    ///   to; required for the reduced tier, which is never reached by omission.
    /// - Throws: before any key material exists when the device cannot protect
    ///   a key at the requested tier.
    func createProfile(username: String, serverURL: String? = nil,
                       consentedTier: KeyProtectionTier? = nil) throws -> Profile {
        Log.keys.info("[ProfileManager] Creating profile: @\(String(describing: username))")
        let tier = try Self.protectionTier(consented: consentedTier)
        let trimmedURL = serverURL?.trimmingCharacters(in: .whitespacesAndNewlines)
        let profile = Profile(username: username, publicKeyHex: "",
                              serverURL: (trimmedURL?.isEmpty == false) ? trimmedURL : nil)
        // The Enclave key the core creates reads its tier from this marker.
        KeyProtectionTier.storeMarker(tier, for: profile.id.uuidString)
        modelContext.insert(profile)
        do {
            try modelContext.save()
        } catch {
            Log.keys.error("[ProfileManager] ❌ Failed to save profile: \(String(describing: error))")
            KeyProtectionTier.deleteMarker(for: profile.id.uuidString)
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

    /// Makes `profile` the active one. Its keys open with the next unlock.
    func switchToProfile(_ profile: Profile) throws {
        if profile.id == currentProfile?.id && profile.isActive {
            return
        }
        // Nothing of the previous profile's authentication may stay in memory.
        clearCachedKey()
        for p in profiles {
            p.isActive = false
        }
        profile.isActive = true
        currentProfile = profile
        try modelContext.save()
        loadProfiles()
        loadActiveProfile()
    }

    /// Why a profile's key could not be opened, comparing the tier it was written
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

    /// Deletes a profile and everything it owns on this device: its core
    /// store, its Enclave key, its tier marker, and any 3.1.1 leftovers.
    func deleteProfile(_ profile: Profile) throws {
        ChatStore.deleteStore(profileID: profile.id)
        MessageKeyStore.delete(for: profile.id)
        CoreMigration.purge(profileID: profile.id, context: modelContext)
        KeyProtectionTier.deleteMarker(for: profile.id.uuidString)
        modelContext.delete(profile)

        // If this was the active profile, activate another one or clear
        if profile.isActive {
            if let firstProfile = profiles.first(where: { $0.id != profile.id }) {
                try switchToProfile(firstProfile)
            } else {
                currentProfile = nil
            }
        }
        try modelContext.save()
        loadProfiles()
    }

    /// Drops the unlock: the authenticated context and the gate. Called on
    /// background and profile switch.
    func clearCachedKey() {
        MessageKeyStore.clearCache()
        MessageKeyGate.shared.lock()
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

