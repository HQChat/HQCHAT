import Foundation
import LocalAuthentication
import SwiftData
import Security

/// Service for resetting all app data (useful for development/testing)
@MainActor
class DataResetService {
    
    /// Reset all app data: keychain, UserDefaults, and SwiftData database
    /// - Parameters:
    ///   - modelContext: The SwiftData model context to clear
    ///   - profileManager: Optional ProfileManager to delete profile keychain items
    /// - Returns: True if successful, false otherwise
    static func resetAllData(modelContext: ModelContext, profileManager: ProfileManager? = nil) -> Bool {
        var success = true
        
        // 1. Clear SwiftData database first (so we can get profile IDs for keychain cleanup)
        // But we need to get profile IDs before deleting them
        var profileIds: [String] = []
        if let profileManager = profileManager {
            profileIds = profileManager.profiles.map { $0.id.uuidString }
        } else {
            // Try to fetch profiles directly
            let descriptor = FetchDescriptor<Profile>()
            if let profiles = try? modelContext.fetch(descriptor) {
                profileIds = profiles.map { $0.id.uuidString }
            }
        }
        
        // Every step runs, even after one fails: this is the account-deletion
        // path, so the database is wiped whatever the keychain answered.
        let keychainCleared = clearAllKeychainItems(profileIds: profileIds)
        let defaultsCleared = clearAllUserDefaults()
        let databaseCleared = clearSwiftDataDatabase(modelContext: modelContext)

        success = success && keychainCleared && defaultsCleared && databaseCleared
        return success
    }
    
    /// Deletes `app.hqchat.profile.*` items of profiles absent from the store: the
    /// residue of an uninstall or of a partial reset.
    private static func clearOrphanedProfileItems(knownProfileIds: [String]) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            // Listing attributes does not read the data, so an item behind
            // `.userPresence` is enumerated without raising a prompt.
            kSecUseAuthenticationContext as String: LAContext.nonInteractive()
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess || status == errSecInteractionNotAllowed,
              let items = result as? [[String: Any]] else {
            // Nothing to enumerate is a success; anything else is reported by the
            // targeted deletes around this.
            return true
        }

        var success = true
        let known = Set(knownProfileIds.map { "app.hqchat.profile.\($0)" })
        for item in items {
            guard let service = item[kSecAttrService as String] as? String,
                  service.hasPrefix("app.hqchat.profile."),
                  !known.contains(service) else { continue }
            if !delete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]) {
                Log.storage.warning("⚠️ Failed to delete orphaned keychain item \(String(describing: service))")
                success = false
            } else {
                Log.storage.info("🧹 Removed orphaned keychain items for \(String(describing: service))")
            }
        }
        return success
    }

    /// Deletes every Keychain item the app owns; true when every delete
    /// succeeded or found nothing. All deletes run even after one fails.
    private static func clearAllKeychainItems(profileIds: [String] = []) -> Bool {
        let generic = kSecClassGenericPassword
        var targets: [(label: String, query: [String: Any])] = [
            // Per-friend channel keys and at-rest message keys, keyed by peer
            // rather than by profile service name.
            ("channel keys", [kSecClass as String: generic, kSecAttrService as String: AESKeyStore.service]),
            ("message keys", [kSecClass as String: generic, kSecAttrService as String: MessageKeyStore.service]),
            // Items written with `kSecUseDataProtectionKeychain` are only found by
            // a query that sets it (macOS has two keychains; iOS has one, where the
            // second form finds nothing left).
            ("message-key store items", [kSecClass as String: generic,
                                         kSecUseDataProtectionKeychain as String: true,
                                         kSecAttrService as String: MessageKeyStore.service]),
            ("key-protection markers", [kSecClass as String: generic,
                                        kSecUseDataProtectionKeychain as String: true,
                                        kSecAttrService as String: KeyProtectionTier.markerService]),
            // Every key pair, in both keychains: these are the only key pairs the
            // app creates, and a tag filter would miss profiles the store forgot.
            ("key pairs (data-protection keychain)", [kSecClass as String: kSecClassKey,
                                                      kSecUseDataProtectionKeychain as String: true]),
            ("key pairs (file keychain)", [kSecClass as String: kSecClassKey,
                                           kSecUseDataProtectionKeychain as String: false]),
        ]
        for profileId in profileIds {
            targets.append(("profile \(profileId)", [kSecClass as String: generic,
                                                     kSecAttrService as String: "app.hqchat.profile.\(profileId)"]))
        }

        var success = true
        for target in targets where !delete(target.query) {
            Log.storage.warning("⚠️ Failed to delete keychain items: \(target.label)")
            success = false
        }
        // iOS keeps the Keychain across an uninstall, so items of profiles this
        // install does not know are swept by service name.
        if !clearOrphanedProfileItems(knownProfileIds: profileIds) { success = false }
        return success
    }

    /// True when the items were deleted or there were none.
    private static func delete(_ query: [String: Any]) -> Bool {
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    /// Clear all UserDefaults keys used by the app
    private static func clearAllUserDefaults() -> Bool {
        // An ALLOWLIST, not `removePersistentDomain(forName:)`. Anything not named
        // here survives a reset, so every omission is a decision.
        //
        // ⚠️ `EulaPrefs.acceptedVersionKey` is deliberately absent. Resetting the
        // app's data destroys identities, contacts and history; it does not
        // un-agree the human sitting in front of it to terms they already read.
        // Re-prompting would be theatre, and Guideline 1.2 asks for agreement,
        // not for a fresh signature per install. It re-prompts by itself when
        // `EulaPrefs.currentVersion` changes, which is the case that should.
        let keys = ["app.hqchat.currentUsername"]
        
        for key in keys {
            UserDefaults.standard.removeObject(forKey: key)
        }
        
        UserDefaults.standard.synchronize()
        return true
    }
    
    /// Clear all SwiftData entities (profiles, friends, messages)
    private static func clearSwiftDataDatabase(modelContext: ModelContext) -> Bool {
        do {
            // Delete all profiles (cascade will delete friends and messages)
            let profileDescriptor = FetchDescriptor<Profile>()
            let profiles = try modelContext.fetch(profileDescriptor)
            for profile in profiles {
                modelContext.delete(profile)
            }
            
            // Also delete any orphaned friends or messages (shouldn't happen with cascade, but just in case)
            let friendDescriptor = FetchDescriptor<Friend>()
            let friends = try modelContext.fetch(friendDescriptor)
            for friend in friends {
                friend.clearAESKeys() // purge Keychain key material
                modelContext.delete(friend)
            }
            
            let messageDescriptor = FetchDescriptor<Message>()
            let messages = try modelContext.fetch(messageDescriptor)
            for message in messages {
                modelContext.delete(message)
            }
            
            try modelContext.save()
            return true
        } catch {
            Log.storage.error("❌ Failed to clear SwiftData database: \(String(describing: error))")
            return false
        }
    }
    
    /// Get the path to the SwiftData database file (for manual deletion if needed)
    /// - Returns: The file path, or nil if not found
    static func getDatabasePath() -> String? {
        #if os(macOS)
        let containerPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library")
            .appendingPathComponent("Containers")
            .appendingPathComponent("martin.rougeron.DissQus")
            .appendingPathComponent("Data")
            .appendingPathComponent("Library")
            .appendingPathComponent("Application Support")
            .appendingPathComponent("default.store")
        return containerPath.path
        #else
        // On iOS the SwiftData store lives in the app's own sandbox.
        guard let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        return appSupport.appendingPathComponent("default.store").path
        #endif
    }
    
    /// Delete the SwiftData database file directly (use with caution)
    /// - Returns: True if successful, false otherwise
    static func deleteDatabaseFile() -> Bool {
        guard let dbPath = getDatabasePath() else {
            return false
        }
        
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: dbPath) {
            do {
                try fileManager.removeItem(atPath: dbPath)
                Log.storage.info("✅ Deleted database file at: \(String(describing: dbPath))")
                return true
            } catch {
                Log.storage.error("❌ Failed to delete database file: \(String(describing: error))")
                return false
            }
        }
        
        return true // File doesn't exist, consider it success
    }
    
    /// Print a summary of all data locations (for debugging)
    static func printDataLocations() {
        Log.storage.info("📁 Data Locations:")
        Log.storage.info("  Keychain:")
        Log.storage.info("    - Profiles: app.hqchat.profile.{profileId}")
        Log.storage.info("  UserDefaults:")
        Log.storage.info("    - app.hqchat.currentUsername")
        if let dbPath = getDatabasePath() {
            Log.storage.info("  SwiftData Database:")
            Log.storage.info("    - \(String(describing: dbPath))")
            let fileManager = FileManager.default
            if fileManager.fileExists(atPath: dbPath) {
                if let attributes = try? fileManager.attributesOfItem(atPath: dbPath),
                   let size = attributes[.size] as? Int64 {
                    Log.storage.info("    - Size: \(String(describing: ByteCountFormatter.string(fromByteCount: size, countStyle: .file)))")
                }
            } else {
                Log.storage.info("    - File does not exist")
            }
        }
    }
}

