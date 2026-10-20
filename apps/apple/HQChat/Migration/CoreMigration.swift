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

    /// Whether 3.1.1 items are still there for a profile the core already
    /// holds: the move was interrupted between the import and the purge, or a
    /// delete failed. Asked without prompting.
    @MainActor
    static func hasLeftovers(profileID: UUID, context: ModelContext) -> Bool {
        guard ChatStore.hasIdentity(profileID: profileID) else { return false }
        if LegacyIdentity.exists(profileID: profileID)
            || !AESKeyStore.accounts(of: profileID).isEmpty
            || !AESKeyStore.orphanedAccounts().isEmpty {
            return true
        }
        let id: UUID? = profileID
        let pending = (try? context.fetchCount(FetchDescriptor<PendingFrame>(predicate: #Predicate { $0.profileID == id }))) ?? 0
        let messages = (try? context.fetchCount(FetchDescriptor<Message>(predicate: #Predicate { $0.profileID == id }))) ?? 0
        let friends = ((try? context.fetch(FetchDescriptor<Friend>())) ?? []).contains { $0.profile?.id == profileID }
        return pending > 0 || messages > 0 || friends
    }

    /// Runs `purge` for every profile the core holds that still has 3.1.1
    /// items. The move purges once the import succeeds; this is what finishes
    /// the job when the process died in between, or a delete failed, since
    /// the move itself never runs again for that profile.
    @MainActor
    static func sweepLeftovers(profiles: [Profile], context: ModelContext) {
        for profile in profiles where hasLeftovers(profileID: profile.id, context: context) {
            Log.keys.info("[CoreMigration] 🧹 3.1.1 items left behind by an earlier move; deleting them")
            purge(profileID: profile.id, context: context)
        }
    }

    /// Deletes a profile's 3.1.1 items: the identity key, sessions and prekey
    /// secrets in the Keychain (with the ones 3.1.1 wrote under no profile),
    /// and its friend, message and pending rows. The Enclave key and the tier
    /// marker stay: the core uses both. A delete that fails is logged, and the
    /// next launch's sweep tries again.
    @MainActor
    static func purge(profileID: UUID, context: ModelContext) {
        LegacyIdentity.delete(profileID: profileID)
        for account in AESKeyStore.accounts(of: profileID) + AESKeyStore.orphanedAccounts() {
            AESKeyStore.delete(account)
        }
        let id: UUID? = profileID
        do {
            for row in try context.fetch(FetchDescriptor<PendingFrame>(predicate: #Predicate { $0.profileID == id })) {
                context.delete(row)
            }
            for row in try context.fetch(FetchDescriptor<Message>(predicate: #Predicate { $0.profileID == id })) {
                context.delete(row)
            }
            for row in try context.fetch(FetchDescriptor<Friend>()) where row.profile?.id == profileID {
                context.delete(row)
            }
            try context.save()
        } catch {
            Log.storage.error("[CoreMigration] ❌ the 3.1.1 rows could not be deleted: \(String(describing: error))")
        }
    }
}
