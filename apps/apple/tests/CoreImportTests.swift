// The move to the core (Migration/CoreImport.swift): a profile's records as
// 3.1.1 kept them, mapped into the core's import and opened by a real engine.
// The keys and the session come from fixtures/legacy-3.1.1-session.json,
// written once by the shipped Swift ratchet with real HQC (the generator ran
// against the 3.1.1 sources before they were deleted), so what is checked is
// the field-for-field mapping of a real session.

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
    func stateSecret() throws -> Data { Data(SHA256.hash(data: key.rawRepresentation)) }
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
    try! Engine(config: Config(serverUrl: "https://hqchat.test", profileId: "p", device: .ios, hqnPins: []),
                vault: TestVault(), store: TestStore())
}

struct Pair: Codable { let pk: Data; let sk: Data }
struct Fixture: Codable {
    let me: Pair
    let friendPk: Data
    let medium: Pair
    let oneTime: Pair
    let session: RatchetSessionState
}
let fixture = try! JSONDecoder().decode(
    Fixture.self,
    from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
)
let me = fixture.me
let friendPk = fixture.friendPk
let medium = fixture.medium
let oneTime = fixture.oneTime
let session = fixture.session
let friendID = peerID(friendPk)
let blockedID = peerID(Data(repeating: 1, count: HQCPublicKeySize))
let vanishedID = peerID(Data(repeating: 2, count: HQCPublicKeySize))

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
            .init(peerID: friendID, username: "friend", publicKey: friendPk,
                  convoTopicID: String(repeating: "c", count: 64),
                  handshakeTopicID: String(repeating: "d", count: 64),
                  session: session, verified: true),
            // An invite nobody accepted yet: no id, so nothing to import.
            .init(peerID: "", username: "pending", publicKey: Data(), convoTopicID: nil,
                  handshakeTopicID: nil, session: nil, accepted: false, inviteSent: true),
            // A request received: the server lists it again, nothing to import.
            .init(peerID: peerID(Data(repeating: 3, count: HQCPublicKeySize)), username: "asking",
                  publicKey: Data(), convoTopicID: nil, handshakeTopicID: nil, session: nil, accepted: false),
            .init(peerID: blockedID, username: "blocked", publicKey: Data(),
                  convoTopicID: String(repeating: "e", count: 64),
                  handshakeTopicID: String(repeating: "f", count: 64), session: nil,
                  blockedAt: Date(timeIntervalSince1970: 1_790_000_000)),
            .init(peerID: vanishedID, username: "gone", publicKey: Data(), convoTopicID: nil,
                  handshakeTopicID: nil, session: nil,
                  vanishedAt: Date(timeIntervalSince1970: 1_790_000_000)),
        ],
        messages: [
            .init(peerID: friendID, messageID: "m3", isOutgoing: false, text: "not seen",
                  timestamp: Date(timeIntervalSince1970: 1_790_000_003), status: nil, read: false),
            .init(peerID: friendID, messageID: "m2", isOutgoing: false, text: "and back",
                  timestamp: Date(timeIntervalSince1970: 1_790_000_002), status: nil, read: true),
            .init(peerID: friendID, messageID: "m1", isOutgoing: true, text: "hello",
                  timestamp: Date(timeIntervalSince1970: 1_790_000_001), status: .delivered, read: false),
        ],
        pending: []
    )
}

print("── Moving a profile to the core ───────────────")

let data = try! CoreImport.importData(from: snapshot())
check(data.peers.count == 3, "requests either way are not friends to import")
check(data.sent.map(\.to) == ["pending"], "a request sent to a handle is kept as sent")
check(data.peers[0].verified, "a verified friend stays verified")
check(data.peers[0].pinnedPublicKey == friendPk, "a full identity key is pinned")
check(data.peers[0].session?.chainStartedAt == CoreImport.milliseconds(session.chainStartedAt),
      "the chain's start time is carried in milliseconds")
check(data.peers[0].session?.pendingInit?.chain.count == 16, "chain ids go from hex to 16 bytes")
check(data.prekeys?.oneTime.map(\.id) == [7] && data.prekeys?.nextId == 8, "one-time prekeys keep their ids")
check(data.messages.first(where: { $0.msgId == "m1" })?.delivery == .delivered, "an outgoing status is carried")
check(data.messages.first(where: { $0.msgId == "m2" })?.delivery == nil, "an incoming message has no delivery status")
check(data.messages.first(where: { $0.msgId == "m1" })?.read == true, "what one sent is never unread")
check(data.peers.first(where: { $0.id == blockedID })?.blockedAt == 1_790_000_000_000, "a block is carried in milliseconds")

let core = engine()
do {
    let effects = try core.importState(data: data, now: 0)
    check(effects == [.tierChanged(tier: .software)], "the engine takes the import")
    let friends = core.friends()
    let friend = friends.first { $0.id == friendID }
    check(friend?.hasSession == true, "the friend arrives with the session")
    check(friend?.unread == 1, "unread from the first message not seen")
    check(friends.first { $0.id == blockedID }?.blockedAt != nil, "a blocked friend stays blocked")
    check(friends.first { $0.id == vanishedID }?.vanishedAt != nil, "a vanished identity stays vanished")
    let history = try core.history(peer: friendID, before: nil, limit: 10)
    check(history.map(\.msgId) == ["m1", "m2", "m3"], "the history comes back in order")
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
