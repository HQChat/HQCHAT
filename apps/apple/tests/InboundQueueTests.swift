// Deferred decryption: frames admitted as ciphertext while locked, opened on
// unlock, and the ratchet/prekey state behind the user's unlock.
//
// Runs the real ConversationRouter, InboundQueue and AESKeyStore over an
// in-memory SwiftData store and an in-memory key backend (an unsigned binary
// cannot write ACL'd Keychain items). The KEM is a stub; the ratchet, the AEAD
// and the frame codec are real.

import Foundation
import CryptoKit
import SwiftData

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// AESKeyStore's backend, in memory, with the lock the Keychain would enforce.
final class MemoryKeyBackend: AESKeyBackend {
    var items: [String: Data] = [:]
    var reads = 0
    var writes = 0
    let lock: () -> Bool

    init(unlocked: @escaping () -> Bool) { self.lock = unlocked }

    func read(_ account: String) -> KeyRead {
        reads += 1
        guard let data = items[account] else { return .absent }
        return lock() ? .value(data) : .locked
    }
    func exists(_ account: String) -> Bool { items[account] != nil }
    func write(_ data: Data, account: String) -> Bool {
        writes += 1
        items[account] = data
        return true
    }
    func delete(_ account: String) { items[account] = nil }
    func accounts() -> [String] { Array(items.keys) }
}

/// The legacy items had no ACL: readable whether or not the user unlocked.
final class LegacyKeyBackend: AESKeyBackend {
    var items: [String: Data] = [:]
    func read(_ account: String) -> KeyRead { items[account].map(KeyRead.value) ?? .absent }
    func exists(_ account: String) -> Bool { items[account] != nil }
    func write(_ data: Data, account: String) -> Bool { false }
    func delete(_ account: String) { items[account] = nil }
    func accounts() -> [String] { Array(items.keys) }
}

/// See RatchetSessionTests: XOR-masked secrets under a tag, implicit rejection.
struct QueueStubKem: RatchetKem {
    func generateKeypair() throws -> (pk: Data, sk: Data) {
        let tag = Data(SymmetricKey(size: .bits256).withUnsafeBytes { Array($0) })
        return (tag, tag)
    }
    func encapsulate(_ pk: Data) throws -> (ct: Data, ss: Data) {
        let ss = Data(SymmetricKey(size: .bits256).withUnsafeBytes { Array($0) })
        let mask = Data(SHA256.hash(data: pk))
        return (mask + Data(zip(ss, mask).map { $0 ^ $1 }), ss)
    }
    func decapsulate(sk: Data, ct: Data) throws -> Data {
        let mask = Data(SHA256.hash(data: sk))
        guard ct.count == 64, ct.prefix(32) == mask else { return Data(SHA256.hash(data: sk + ct)) }
        return Data(zip(ct.suffix(32), mask).map { $0 ^ $1 })
    }
}

final class Lock { var unlocked = true }
final class Recorder {
    var receipts: [(peer: String, msgId: String)] = []
    var notified = 0
    var onReceipt: (() -> Void)?
}

let kem = QueueStubKem()
let lock = Lock()
var keys = MemoryKeyBackend(unlocked: { lock.unlocked })
var legacy = LegacyKeyBackend()
AESKeyStore.isUnlocked = { lock.unlocked }
AESKeyStore.backend = keys
AESKeyStore.legacy = legacy

func hex64(_ seed: String) -> String { SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined() }

/// A contact on the other end, with their side of the session.
struct Peer {
    let friend: Friend
    var state: RatchetSessionState
    var sent: [String] = []

    /// A frame exactly as the wire would carry it.
    mutating func frame(to me: String, kind: ConversationFrame.Kind = .message,
                        msgId: String = UUID().uuidString) -> Data {
        let sealed = try! RatchetSession.seal(kem: kem, state: &state)
        let fields = ConversationFrame(t: kind, sender: friend.peerID, to: me, msgId: msgId,
                                       cid: sealed.header.cid, n: sealed.header.n,
                                       pn: sealed.header.pn, rk: sealed.header.rk,
                                       kemCt: sealed.header.kemCt)
        let aad = fields.header()!
        let payload = try! AESService.encryptRaw(plaintext: "body \(msgId)",
                                                 key: SymmetricKey(data: sealed.key), aad: aad)
        if kind == .message { sent.append(msgId) }
        return fields.withPayload(payload).encoded()!
    }
}

@MainActor
struct World {
    let ctx: ModelContext
    let me: Profile
    let router: ConversationRouter
    let recorder: Recorder

    /// We opened the session (so the peer's frames are plain messages); the
    /// peer answered from our init.
    func addPeer(_ name: String) -> Peer {
        let friend = Friend(username: name, peerID: hex64(name), publicKey: Data(), profile: me)
        friend.convoTopicID = hex64("cv-" + name)
        friend.handshakeTopicID = hex64("hs-" + name)
        friend.inviteStatus = .accepted
        ctx.insert(friend)
        try? ctx.save()

        let identity = try! kem.generateKeypair()
        let medium = try! kem.generateKeypair()
        let started = try! RatchetSession.startAsInitiator(
            kem: kem, bundle: PrekeyBundle(identityPk: identity.pk, mediumPk: medium.pk,
                                           oneTimePk: nil, oneTimeId: nil))
        let theirs = RatchetSession.startAsResponder(
            kem: kem, secrets: PrekeySecrets(identitySk: identity.sk, mediumSk: medium.sk) { _ in nil },
            header: started.header)!
        let was = lock.unlocked
        lock.unlocked = true
        friend.ratchetSession = started.state
        lock.unlocked = was
        return Peer(friend: friend, state: theirs)
    }

    func deliver(_ raw: Data, from peer: Peer) async {
        let (frame, aad) = ConversationFrame.decodeReporting(raw).result!
        await router.handle(frame, aad: aad, topic: peer.friend.topics!.conversation, raw: raw)
    }

    func pending() -> Int { (try? ctx.fetchCount(FetchDescriptor<PendingFrame>())) ?? -1 }

    func stored(from peer: Peer) -> [String] {
        let id = peer.friend.peerID
        let rows = (try? ctx.fetch(FetchDescriptor<Message>(
            predicate: #Predicate { $0.friend?.peerID == id && !$0.isOutgoing }))) ?? []
        return rows.compactMap(\.messageId)
    }

    func receipts(to peer: Peer) -> [String] {
        recorder.receipts.filter { $0.peer == peer.friend.peerID }.map(\.msgId)
    }

    func unlockAndDrain() async {
        lock.unlocked = true
        router.drainPending()
        await router.queue.waitUntilIdle()
    }
}

@MainActor
func makeWorld() -> World {
    let container = try! ModelContainer(
        for: Profile.self, Friend.self, Message.self, PendingFrame.self,
        configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let ctx = container.mainContext
    let me = Profile(username: "me", publicKeyHex: hex64("me-key"))
    me.isActive = true
    ctx.insert(me)
    try? ctx.save()
    let recorder = Recorder()
    let router = ConversationRouter(
        modelContext: ctx, profileManager: ProfileManager(modelContext: ctx), prekeys: nil,
        kem: kem,
        publish: { _, _ in },
        sendReceipt: { msgId, friend in
            recorder.receipts.append((friend.peerID, msgId))
            recorder.onReceipt?()
        },
        notifyMessage: { _ in recorder.notified += 1 },
        recount: { _, _ in })
    // Keep the container alive for the world's lifetime.
    worlds.append(container)
    return World(ctx: ctx, me: me, router: router, recorder: recorder)
}
var worlds: [ModelContainer] = []

// ── The checks ───────────────────────────────────────────────────────────────

@MainActor
func run() async {
    print("── Locked: admitted as ciphertext, nothing read ─")
    do {
        let w = makeWorld()
        var bob = w.addPeer("bob")
        lock.unlocked = false
        let readsBefore = keys.reads, writesBefore = keys.writes
        for _ in 0..<5 { await w.deliver(bob.frame(to: w.me.peerID), from: bob) }
        await w.deliver(bob.frame(to: w.me.peerID, kind: .receipt), from: bob)
        await w.router.queue.waitUntilIdle()

        check(w.pending() == 6, "six frames queued while locked (got \(w.pending()))")
        check(w.stored(from: bob).isEmpty, "nothing opened while locked")
        check(keys.reads == readsBefore, "no ratchet state read while locked")
        check(keys.writes == writesBefore, "no ratchet state written while locked")
        check(w.recorder.notified == 5, "each message notified once on arrival, the receipt not (got \(w.recorder.notified))")
        check(InboundQueue.unopenedMessageCount(modelContext: w.ctx, profileID: w.me.id) == 5,
              "the unread count includes the five unopened messages, not the receipt")
        check(bob.friend.hasSession, "hasSession is answered while locked")
        check(keys.reads == readsBefore, "…without reading the session")

        // A broker re-delivery of a queued frame is not admitted twice.
        let again = bob.frame(to: w.me.peerID)
        await w.deliver(again, from: bob)
        await w.deliver(again, from: bob)
        check(w.pending() == 7, "a re-delivered frame is queued once")
        check(w.recorder.notified == 6, "…and notified once")

        print("── Unlock: the backlog opens in order ──────────")
        await w.unlockAndDrain()
        check(w.pending() == 0, "the queue is empty after the drain (got \(w.pending()))")
        check(Set(w.stored(from: bob)) == Set(bob.sent), "all six messages stored")
        check(w.receipts(to: bob) == bob.sent, "receipts sent in arrival order")
        check(keys.writes > writesBefore, "the advanced state was written once unlocked")
    }

    print("── Live frames interleave with a backlog ───────")
    do {
        let w = makeWorld()
        var bob = w.addPeer("bob")
        var carol = w.addPeer("carol")
        lock.unlocked = false
        for _ in 0..<200 { await w.deliver(bob.frame(to: w.me.peerID), from: bob) }
        check(w.pending() == 200, "a 200-frame backlog is queued")

        lock.unlocked = true
        w.router.drainPending()
        // Live traffic from both while the backlog drains.
        var ticksDuringLive = 0
        for _ in 0..<100 {
            await w.deliver(bob.frame(to: w.me.peerID), from: bob)
            await w.deliver(carol.frame(to: w.me.peerID), from: carol)
            ticksDuringLive += 1
            await Task.yield()
        }
        let backlogLeftWhenLiveDone = w.pending()
        await w.router.queue.waitUntilIdle()

        check(ticksDuringLive == 100, "live frames were admitted while the backlog drained")
        check(backlogLeftWhenLiveDone > 0, "…and admission did not wait for the backlog to finish (\(backlogLeftWhenLiveDone) still queued)")
        check(w.stored(from: bob).count == 300, "every frame from bob stored (got \(w.stored(from: bob).count))")
        check(w.receipts(to: bob) == bob.sent, "bob's backlog and live frames opened in arrival order")
        check(w.receipts(to: carol) == carol.sent, "carol's live frames opened in order")
        check(w.pending() == 0, "nothing left queued")
    }

    print("── The drain never holds the main actor ────────")
    do {
        let w = makeWorld()
        var bob = w.addPeer("bob")
        lock.unlocked = false
        let frames = 500
        for _ in 0..<frames { await w.deliver(bob.frame(to: w.me.peerID), from: bob) }

        var ticks = 0
        var stop = false
        let ticker = Task { @MainActor in
            while !stop { ticks += 1; await Task.yield() }
        }
        let started = Date()
        await w.unlockAndDrain()
        let took = Date().timeIntervalSince(started)
        stop = true
        await ticker.value
        check(w.stored(from: bob).count == frames, "a \(frames)-frame backlog drained")
        check(ticks >= frames / 2, "other main-actor work ran throughout the drain (\(ticks) turns over \(frames) frames, \(String(format: "%.2f", took))s)")
    }

    print("── Locking mid-drain stops it, frames kept ─────")
    do {
        let w = makeWorld()
        var bob = w.addPeer("bob")
        lock.unlocked = false
        for _ in 0..<50 { await w.deliver(bob.frame(to: w.me.peerID), from: bob) }

        w.recorder.onReceipt = { if w.recorder.receipts.count == 10 { lock.unlocked = false } }
        lock.unlocked = true
        w.router.drainPending()
        await w.router.queue.waitUntilIdle()
        let writesWhileLocked = keys.writes
        check(w.stored(from: bob).count == 10, "the drain stopped at the lock (stored \(w.stored(from: bob).count))")
        check(w.pending() == 40, "the rest stay queued (got \(w.pending()))")

        w.router.drainPending()
        await w.router.queue.waitUntilIdle()
        check(keys.writes == writesWhileLocked, "a drain asked for while locked does nothing")

        w.recorder.onReceipt = nil
        await w.unlockAndDrain()
        check(w.stored(from: bob).count == 50, "the next unlock finishes it")
        check(w.receipts(to: bob) == bob.sent, "…in order")
    }

    print("── Replays after a crash lose nothing ──────────")
    do {
        let w = makeWorld()
        var bob = w.addPeer("bob")
        let account = Friend.aesAccount(profileID: w.me.id, peerID: bob.friend.peerID, suffix: "ratchet")
        lock.unlocked = true
        let before = keys.items[account]
        let raw = bob.frame(to: w.me.peerID)
        await w.deliver(raw, from: bob)
        await w.router.queue.waitUntilIdle()
        check(w.stored(from: bob).count == 1, "the frame opened")

        // Crash after the message was stored, before the state was: replayed.
        keys.items[account] = before
        await w.deliver(raw, from: bob)
        await w.router.queue.waitUntilIdle()
        check(w.stored(from: bob).count == 1, "replayed after a crash before the state write: no duplicate")
        check(keys.items[account] != before, "…and the state advances this time")
        check(w.pending() == 0, "…and the frame is gone")

        // Crash after the state was stored, before the frame was deleted.
        let advanced = keys.items[account]
        await w.deliver(raw, from: bob)
        await w.router.queue.waitUntilIdle()
        check(w.stored(from: bob).count == 1, "replayed after a crash before the delete: no duplicate")
        check(keys.items[account] == advanced, "…the spent key opens nothing and nothing is written")
        check(w.pending() == 0, "…and the frame is dropped")

        // The next frame still opens.
        await w.deliver(bob.frame(to: w.me.peerID), from: bob)
        await w.router.queue.waitUntilIdle()
        check(w.stored(from: bob).count == 2, "the conversation carries on")
    }

    print("── Nothing derived from a locked read is written ──")
    do {
        let w = makeWorld()
        let bob = w.addPeer("bob")
        lock.unlocked = false
        let account = Friend.aesAccount(profileID: w.me.id, peerID: bob.friend.peerID, suffix: "ratchet")
        let held = keys.items[account]
        let writes = keys.writes
        check(bob.friend.ratchetSession == nil, "a locked session reads as nil")
        check(AESKeyStore.read(account) == .locked, "…but the store says locked, not absent")
        bob.friend.ratchetSession = try! RatchetSession.startAsInitiator(
            kem: kem, bundle: PrekeyBundle(identityPk: Data(count: 32), mediumPk: Data(count: 32),
                                           oneTimePk: nil, oneTimeId: nil)).state
        check(keys.items[account] == held && keys.writes == writes,
              "a session derived while locked does not replace the real one")
        check(AESKeyStore.set(Data([1]), account: account) == false, "AESKeyStore.set refuses while locked")
        AESKeyStore.delete("nothing-here")

        // Prekeys: a locked store is not an absent one.
        let prekeyAccount = PrekeyService.account(for: w.me.id)
        keys.items[prekeyAccount] = Data("{}".utf8)
        let prekeys = PrekeyService(api: APIClient(auth: AuthService())) { w.me.id }
        await prekeys.ensurePublished()
        check(keys.items[prekeyAccount] == Data("{}".utf8) && keys.writes == writes,
              "ensurePublished leaves a locked prekey store alone (no mint, no publish)")
        lock.unlocked = true
    }

    print("── Legacy items move under the ACL ─────────────")
    do {
        keys = MemoryKeyBackend(unlocked: { lock.unlocked })
        legacy = LegacyKeyBackend()
        AESKeyStore.backend = keys
        AESKeyStore.legacy = legacy
        let mine = UUID(), other = UUID()
        let ratchet = Friend.aesAccount(profileID: mine, peerID: hex64("bob"), suffix: "ratchet")
        let prekeys = PrekeyService.account(for: mine)
        let foreign = PrekeyService.account(for: other)
        legacy.items = [ratchet: Data([1]), prekeys: Data([2]), foreign: Data([3])]

        lock.unlocked = false
        check(AESKeyStore.exists(ratchet), "a legacy item exists before migration")
        check(AESKeyStore.read(ratchet) == .locked, "…and reads as locked, not as the value")
        check(AESKeyStore.migrateLegacyItems(profileID: mine) == 0, "nothing moves while locked")

        lock.unlocked = true
        check(AESKeyStore.migrateLegacyItems(profileID: mine) == 2, "the profile's two items move on unlock")
        check(keys.items[ratchet] == Data([1]) && keys.items[prekeys] == Data([2]), "…values unchanged")
        check(legacy.items.keys.sorted() == [foreign], "…their unprotected copies are gone; another profile's wait for it")
        check(AESKeyStore.migrateLegacyItems(profileID: mine) == 0, "a second pass moves nothing")

        // A crash between the copy and the delete leaves both; the next pass only deletes.
        legacy.items[ratchet] = Data([9])
        check(AESKeyStore.read(ratchet) == .value(Data([1])), "the protected copy wins")
        AESKeyStore.migrateLegacyItems(profileID: mine)
        check(legacy.items[ratchet] == nil && keys.items[ratchet] == Data([1]),
              "…and the next pass deletes the stale legacy copy without copying it")

        // Inline, on first read, for an item the sweep has not reached.
        legacy.items[foreign] = Data([3])
        check(AESKeyStore.read(foreign) == .value(Data([3])), "a legacy item read while unlocked is moved and returned")
        check(legacy.items[foreign] == nil && keys.items[foreign] == Data([3]), "…and now lives under the ACL")
    }
}

await run()
finish()
