// The move to the core (Services/CoreImport.swift): a profile's records as the
// Swift implementation keeps them, mapped into the core's import and opened
// by a real engine. The session is made by the app's own ratchet with real
// HQC, so what is checked is the field-for-field mapping, not a fixture.

import CryptoKit
import Foundation
import HQChatCore

final class TestVault: KeyVault, @unchecked Sendable {
    private let key = P256.KeyAgreement.PrivateKey()
    func create() throws -> Tier { .software }
    func devicePublicKey() throws -> Data { key.publicKey.x963Representation }
    func agree(ephemeralPublic: Data) throws -> Data {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
        return try key.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
    }
    func tier() -> Tier { .software }
}

final class TestStore: Store, @unchecked Sendable {
    private var blobs: [String: Data] = [:]
    private let lock = NSLock()
    func get(key: String) -> Data? { lock.withLock { blobs[key] } }
    func put(key: String, value: Data) throws { lock.withLock { blobs[key] = value } }
    func delete(key: String) { lock.withLock { _ = blobs.removeValue(forKey: key) } }
    func list(prefix: String) -> [String] { lock.withLock { blobs.keys.filter { $0.hasPrefix(prefix) }.sorted() } }
}

func peerID(_ pk: Data) -> String {
    SHA256.hash(data: Data(pk.hexString.lowercased().utf8)).map { String(format: "%02x", $0) }.joined()
}

func engine() -> Engine {
    try! Engine(config: Config(serverUrl: "https://hqchat.test", profileId: "p", device: .ios),
                vault: TestVault(), store: TestStore())
}

let hqc = HQCKem()
let me = try! hqc.generateKeypair()
let friendKey = try! hqc.generateKeypair()
let medium = try! hqc.generateKeypair()
let friendID = peerID(friendKey.pk)
let started = try! RatchetSession.startAsInitiator(
    kem: hqc,
    bundle: PrekeyBundle(identityPk: friendKey.pk, mediumPk: medium.pk, oneTimePk: nil, oneTimeId: nil)
)
let oneTime = try! hqc.generateKeypair()

func snapshot() -> LegacySnapshot {
    LegacySnapshot(
        identityPublicKey: me.pk,
        identitySecretKey: me.sk,
        prekeys: PrekeyStore(
            mediumPk: medium.pk, mediumSk: medium.sk,
            oneTime: ["7": .init(pk: oneTime.pk, sk: oneTime.sk)],
            nextId: 8, rotatedAt: Date(timeIntervalSince1970: 1_790_000_000)
        ),
        friends: [
            .init(peerID: friendID, username: "friend", publicKey: friendKey.pk,
                  convoTopicID: String(repeating: "c", count: 64),
                  handshakeTopicID: String(repeating: "d", count: 64),
                  session: started.state),
            // An invite nobody accepted yet: no id, so nothing to import.
            .init(peerID: "", username: "pending", publicKey: Data(), convoTopicID: nil,
                  handshakeTopicID: nil, session: nil),
        ],
        messages: [
            .init(peerID: friendID, messageID: "m2", isOutgoing: false, text: "and back",
                  timestamp: Date(timeIntervalSince1970: 1_790_000_002), status: nil),
            .init(peerID: friendID, messageID: "m1", isOutgoing: true, text: "hello",
                  timestamp: Date(timeIntervalSince1970: 1_790_000_001), status: .delivered),
        ],
        pending: []
    )
}

print("── Moving a profile to the core ───────────────")

let data = try! CoreImport.importData(from: snapshot())
check(data.peers.count == 1, "an invite without an id is not a friend to import")
check(data.peers[0].pinnedPublicKey == friendKey.pk, "a full identity key is pinned")
check(data.peers[0].session?.chainStartedAt == CoreImport.milliseconds(started.state.chainStartedAt),
      "the chain's start time is carried in milliseconds")
check(data.peers[0].session?.pendingInit?.chain.count == 16, "chain ids go from hex to 16 bytes")
check(data.prekeys?.oneTime.map(\.id) == [7] && data.prekeys?.nextId == 8, "one-time prekeys keep their ids")
check(data.messages.first(where: { $0.msgId == "m1" })?.delivery == .delivered, "an outgoing status is carried")
check(data.messages.first(where: { $0.msgId == "m2" })?.delivery == nil, "an incoming message has no delivery status")

let core = engine()
do {
    let effects = try core.importState(data: data, now: 0)
    check(effects == [.tierChanged(tier: .software)], "the engine takes the import")
    let friends = core.friends()
    check(friends.count == 1 && friends[0].hasSession, "the friend arrives with the session")
    let history = try core.history(peer: friendID, before: nil, limit: 10)
    check(history.map(\.msgId) == ["m1", "m2"], "the history comes back in order")
    check(history.first?.delivery == .delivered, "with its statuses")
} catch {
    check(false, "the import failed: \(error)")
}

var bad = snapshot()
bad.friends[0].session?.seenChains = ["not hex"]
check((try? CoreImport.importData(from: bad)) == nil, "a chain id that is not hex refuses the mapping")
bad = snapshot()
bad.friends[0].session?.prevSendN = -1
do {
    _ = try CoreImport.importData(from: bad)
    check(false, "a negative counter is refused")
} catch CoreImportError.outOfRange {
    check(true, "a negative counter is refused, not wrapped")
} catch {
    check(false, "unexpected \(error)")
}

var truncated = try! CoreImport.importData(from: snapshot())
truncated.identitySecretKey = truncated.identitySecretKey.prefix(10)
let empty = engine()
check((try? empty.importState(data: truncated, now: 0)) == nil, "a truncated key refuses the import")
check((try? empty.importState(data: data, now: 0)) != nil, "and nothing was kept: the move can run again")

finish()
