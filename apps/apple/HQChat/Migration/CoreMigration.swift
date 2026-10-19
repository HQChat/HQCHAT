// TRANSITION CODE (see CoreImport.swift): runs the move once per profile, on
// the first unlock after the update, then deletes what 3.1.1 left behind.

import Foundation
import SwiftData

enum CoreMigration {
    enum Failure: LocalizedError {
        /// The user did not unlock: nothing was read, the next launch asks again.
        case notUnlocked
        /// The identity key could not be read.
        case identityUnreadable
        case read(Error)
        case importRefused(Error)

        var errorDescription: String? {
            switch self {
            case .notUnlocked:
                return "Unlock HQChat to finish updating your data."
            case .identityUnreadable:
                return "Your identity key could not be read. Try again; nothing was lost."
            case let .read(error), let .importRefused(error):
                return "Your data could not be updated (\(error.localizedDescription)). Nothing was lost; the app tries again at the next launch."
            }
        }
    }

    /// Whether `profile` still holds 3.1.1 data the core has not taken yet.
    static func isNeeded(for profile: Profile) -> Bool {
        !ChatStore.hasIdentity(profileID: profile.id) && LegacyIdentity.exists(profileID: profile.id)
    }

    /// Moves `profile` into `store`'s core: reads everything under the unlock,
    /// imports it (all or nothing), and only then deletes the old items. A
    /// failure before the import deletes nothing, so the move can run again.
    /// Returns how many messages could not be opened and were left out.
    @MainActor
    static func run(profile: Profile, into store: ChatStore, context: ModelContext) async throws -> Int {
        await MessageKeyGate.shared.unlock(reason: "Update your HQChat data", retry: true)
        guard MessageKeyGate.shared.isUnlocked else { throw Failure.notUnlocked }
        guard let secretKey = LegacyIdentity.readSecretKey(profileID: profile.id) else {
            throw Failure.identityUnreadable
        }
        let snapshot: LegacySnapshot
        let unreadable: Int
        do {
            (snapshot, unreadable) = try LegacySnapshot.read(profile: profile, secretKey: secretKey, context: context)
        } catch {
            throw Failure.read(error)
        }
        do {
            try await store.importState(try CoreImport.importData(from: snapshot))
        } catch {
            throw Failure.importRefused(error)
        }
        purge(profileID: profile.id, context: context)
        profile.publicKeyHex = ""
        profile.clientID = store.myID
        try? context.save()
        Log.keys.info("[CoreMigration] ✅ profile moved to the core (\(unreadable) unreadable message(s) left out)")
        return unreadable
    }

    /// Deletes a profile's 3.1.1 items: the identity key, sessions and prekey
    /// secrets in the Keychain, and its friend, message and pending rows. The
    /// Enclave key and the tier marker stay: the core uses both.
    @MainActor
    static func purge(profileID: UUID, context: ModelContext) {
        LegacyIdentity.delete(profileID: profileID)
        for account in AESKeyStore.accounts(of: profileID) { AESKeyStore.delete(account) }
        let id: UUID? = profileID
        for row in (try? context.fetch(FetchDescriptor<PendingFrame>(predicate: #Predicate { $0.profileID == id }))) ?? [] {
            context.delete(row)
        }
        for row in (try? context.fetch(FetchDescriptor<Message>(predicate: #Predicate { $0.profileID == id }))) ?? [] {
            context.delete(row)
        }
        for row in (try? context.fetch(FetchDescriptor<Friend>())) ?? [] where row.profile?.id == profileID {
            context.delete(row)
        }
        try? context.save()
    }
}
