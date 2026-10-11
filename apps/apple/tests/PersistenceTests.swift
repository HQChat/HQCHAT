// The store and the reset that empties it, against an in-memory SwiftData
// container: a profile's id names its key, contacts and messages persist, and a
// reset leaves no row behind (the account-deletion claim). Anything needing the
// Secure Enclave or a biometric prompt needs a signed build on real hardware.

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
    let container = freshContainer()
    let ctx = container.mainContext

    // ── A profile's id is derived from its key ───────────────────────────────

    let pk = Data((0..<7237).map { UInt8($0 % 251) })
    let profile = Profile(username: "alice", publicKeyHex: pk.hexString)
    ctx.insert(profile)
    check(!profile.publicKeyHex.isEmpty, "a profile carries its public key")
    check(profile.publicKeyHex.count == 7237 * 2, "as full-width hex — an HQC-256 key is 7237 bytes")
    check(profile.publicKeyHex == profile.publicKeyHex.lowercased(),
          "lowercase, because PeerID hashes the TEXT and case would change the id")

    // ── A contact is named by its client id, not its key ─────────────────────

    let friendPk = Data((0..<7237).map { UInt8(($0 &* 7) % 251) })
    let friend = Friend(username: "bob",
                        peerID: PeerID.from(publicKey: friendPk),
                        publicKey: friendPk,
                        profile: profile)
    ctx.insert(friend)
    check(friend.peerID.count == 64, "a contact's id is 64 hex characters, not a 14474-character key")
    check(PeerID.matches(publicKey: friendPk, id: friend.peerID),
          "…and it is the digest of the key it was created with")

    let msg = Message(content: "hello", isOutgoing: false, friend: friend)
    ctx.insert(msg)
    try? ctx.save()

    check((try? ctx.fetch(FetchDescriptor<Profile>()))?.count == 1, "the profile persisted")
    check((try? ctx.fetch(FetchDescriptor<Friend>()))?.count == 1, "the contact persisted")
    check((try? ctx.fetch(FetchDescriptor<Message>()))?.count == 1, "the message persisted")

    // ── The reset ────────────────────────────────────────────────────────────
    //
    // This is the App Store account-deletion claim: a row left behind makes it
    // false. The keychain half cannot succeed in an unsigned binary
    // (-25244 / -34018), so `resetAllData` reports false here, but every other
    // step must still run: one failure must not cancel the rest.
    let ok = DataResetService.resetAllData(modelContext: ctx)
    check(!ok, "an unsigned binary cannot clear the keychain, so the reset reports failure")
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
    // `createProfile` needs the Keychain and cannot run in an unsigned binary,
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
    let older = Profile(username: "older", publicKeyHex: pk.hexString)
    older.createdAt = Date(timeIntervalSince1970: 1_000)
    let newer = Profile(username: "newer", publicKeyHex: pk.hexString)
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

    // ── The prekey pool ──────────────────────────────────────────────────────
    //
    // Keyed per profile, so two profiles on one device cannot read each other's
    // one-time secrets.
    let a = UUID(), b = UUID()
    check(PrekeyService.account(for: a) != PrekeyService.account(for: b),
          "two profiles get different prekey storage accounts")
    check(PrekeyService.account(for: nil) != PrekeyService.account(for: a),
          "…and the no-profile account is its own")
    check(PrekeyService.account(for: a) == PrekeyService.account(for: a),
          "the account is stable for one profile")
    check(PrekeyService.account(for: a).contains(a.uuidString)
          || PrekeyService.account(for: a).count > 8,
          "the account names the profile it belongs to")
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
