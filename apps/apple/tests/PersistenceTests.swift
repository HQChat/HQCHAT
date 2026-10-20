// The store and the reset that empties it, against an in-memory SwiftData
// container: a profile's id, the 3.1.1 rows the move leaves to delete, and a
// reset that leaves no row and no core store behind (the account-deletion
// claim). Anything needing the Secure Enclave or a biometric prompt needs a
// signed build on real hardware.

import Foundation
import SwiftData

// ── The fixture ──────────────────────────────────────────────────────────────

@MainActor
func freshContainer() -> ModelContainer {
    let config = ModelConfiguration(isStoredInMemoryOnly: true)
    return try! ModelContainer(for: Profile.self, Friend.self, Message.self, PendingFrame.self, configurations: config)
}

@MainActor
func run() {
    // Never the real Application Support: the reset below deletes the root.
    ChatStore.rootOverride = FileManager.default.temporaryDirectory
        .appendingPathComponent("hqchat-tests-\(UUID().uuidString)", isDirectory: true)
    let container = freshContainer()
    let ctx = container.mainContext

    // ── A profile's id ───────────────────────────────────────────────────────

    let pk = Data((0..<7237).map { UInt8($0 % 251) })
    let legacy = Profile(username: "alice", publicKeyHex: pk.hexString)
    ctx.insert(legacy)
    check(legacy.peerID.count == 64, "a 3.1.1 profile's id is derived from its key until the move")
    legacy.clientID = String(repeating: "ab", count: 32)
    check(legacy.peerID == legacy.clientID, "the core's id wins once known")
    let fresh = Profile(username: "carol", publicKeyHex: "")
    check(fresh.peerID.isEmpty && fresh.publicKey == nil, "a profile made by the core has no 3.1.1 key")
    ctx.insert(fresh)

    // ── The 3.1.1 rows the move reads, then deletes ──────────────────────────

    let friend = Friend(username: "bob", peerID: String(repeating: "b", count: 64), profile: legacy)
    ctx.insert(friend)
    let msg = Message(timestamp: Date(), isOutgoing: false, friend: friend, profileID: legacy.id)
    ctx.insert(msg)
    ctx.insert(PendingFrame(profileID: legacy.id, topic: "cv/x", raw: Data([1]), seq: 1))
    try? ctx.save()
    check((try? ctx.fetch(FetchDescriptor<Friend>()))?.count == 1, "the 3.1.1 contact is there")

    // A row from before message ids were kept is imported under an id derived
    // from the row itself, so a retried import writes over the slots of the
    // one that failed instead of leaving them beside its own.
    let otherMsg = Message(timestamp: Date(), isOutgoing: true, friend: friend, profileID: legacy.id)
    ctx.insert(otherMsg)
    try? ctx.save()
    let firstID = try? LegacySnapshot.legacyMessageID(for: msg)
    check(firstID != nil && firstID == (try? LegacySnapshot.legacyMessageID(for: msg)),
          "a row without an id gets the same one every time it is read")
    check(firstID != (try? LegacySnapshot.legacyMessageID(for: otherMsg)), "…and two rows get two ids")

    // The core holding the profile while its 3.1.1 rows are still there is a
    // move that died before the purge: the launch's sweep finishes it.
    check(!CoreMigration.hasLeftovers(profileID: legacy.id, context: ctx),
          "rows the core has not taken are not leftovers: the move has not run")
    let legacyRoot = try! ChatStore.storeDirectory(for: legacy.id)
    try! FileManager.default.createDirectory(at: legacyRoot, withIntermediateDirectories: true)
    try! Data([1]).write(to: legacyRoot.appendingPathComponent("state"))
    check(CoreMigration.hasLeftovers(profileID: legacy.id, context: ctx),
          "a profile the core holds, with 3.1.1 rows still there, has leftovers")
    CoreMigration.sweepLeftovers(profiles: [legacy, fresh], context: ctx)
    check(!CoreMigration.hasLeftovers(profileID: legacy.id, context: ctx), "the sweep deletes them")
    try? FileManager.default.removeItem(at: legacyRoot)
    check((try? ctx.fetch(FetchDescriptor<Friend>()))?.count == 0, "the sweep's purge deletes the 3.1.1 contacts")
    check((try? ctx.fetch(FetchDescriptor<Message>()))?.count == 0, "…their messages")
    check((try? ctx.fetch(FetchDescriptor<PendingFrame>()))?.count == 0, "…and the frames never opened")
    check((try? ctx.fetch(FetchDescriptor<Profile>()))?.count == 2, "but keeps the profile")

    // A core store on disk, for the reset to remove.
    let root = try! ChatStore.storeDirectory(for: fresh.id)
    try! FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    try! Data([1]).write(to: root.appendingPathComponent("state"))
    check(ChatStore.hasIdentity(profileID: fresh.id), "a core store with a state is an identity")

    // ── The reset ────────────────────────────────────────────────────────────
    //
    // This is the App Store account-deletion claim: a row left behind makes it
    // false. The keychain half cannot succeed in an unsigned binary
    // (-25244 / -34018), so `resetAllData` reports false here, but every other
    // step must still run: one failure must not cancel the rest.
    let ok = DataResetService.resetAllData(modelContext: ctx)
    check(!ok, "an unsigned binary cannot clear the keychain, so the reset reports failure")
    check(!ChatStore.hasIdentity(profileID: fresh.id), "after a reset, no core store is left")
    for (name, n) in [
        ("profiles", (try? ctx.fetch(FetchDescriptor<Profile>()))?.count ?? -1),
        ("contacts", (try? ctx.fetch(FetchDescriptor<Friend>()))?.count ?? -1),
        ("messages", (try? ctx.fetch(FetchDescriptor<Message>()))?.count ?? -1),
    ] {
        check(n == 0,
              "after a reset, \(name) is empty (got \(n)) — a step that failed "
              + "earlier must not cancel the database wipe")
    }

    // And again on the emptied store: still reports the keychain failure, still
    // leaves nothing behind.
    _ = DataResetService.resetAllData(modelContext: ctx)
    check((try? ctx.fetch(FetchDescriptor<Profile>()))?.count == 0,
          "a second reset is harmless")

    // ── The profile manager ──────────────────────────────────────────────────
    //
    // `createProfile` writes a tier marker and cannot run in an unsigned binary,
    // but everything that reads the store can — and the reads carry the two
    // properties that matter.

    let container2 = freshContainer()
    let ctx2 = container2.mainContext
    let pm = ProfileManager(modelContext: ctx2)

    pm.loadProfiles()
    check(pm.profiles.isEmpty, "a fresh store has no profiles")
    pm.loadActiveProfile()
    check(pm.currentProfile == nil, "…and none is active")

    // Newest first. The profile picker shows them in this order, and a stable
    // sort is what stops it reshuffling under the user between launches.
    let older = Profile(username: "older", publicKeyHex: "")
    older.createdAt = Date(timeIntervalSince1970: 1_000)
    let newer = Profile(username: "newer", publicKeyHex: "")
    newer.createdAt = Date(timeIntervalSince1970: 2_000)
    ctx2.insert(older); ctx2.insert(newer)
    try? ctx2.save()

    pm.loadProfiles()
    check(pm.profiles.count == 2, "both profiles load")
    check(pm.profiles.first?.username == "newer", "newest first, so the picker does not reshuffle")

    // The active profile is the one flagged, and settling it tells the message
    // key store whose unlock policy applies — one place where "the active
    // profile" is decided, and one place that can go stale.
    newer.isActive = true
    try? ctx2.save()
    pm.loadActiveProfile()
    check(pm.currentProfile?.username == "newer", "the flagged profile is the active one")

    newer.isActive = false
    try? ctx2.save()
    pm.loadActiveProfile()
    check(pm.currentProfile == nil, "unflagging it leaves none active, rather than the first row")
}

// Everything above is @MainActor because SwiftData's mainContext is, and a
// slice's main.swift has no async entry point to await from.
//
// `assumeIsolated`, NOT a Task plus a semaphore: top-level code already runs ON
// the main thread, so blocking it to wait for a @MainActor task is a deadlock —
// the task needs the very thread the semaphore is holding. Verified the hard
// way; that version hung until it was killed.
MainActor.assumeIsolated { run() }

finish()
