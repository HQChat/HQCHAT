// TRANSITION CODE (see CoreImport.swift): the 3.1.1 friend row, kept only so
// the move to the core can read it and then delete it. Nothing else uses it.

import Foundation
import SwiftData

/// HQC-256 public key size, in bytes.
let HQCPublicKeySize = 7237

/// The 3.1.1 friend model, by a name that files whose own types shadow
/// `Friend` (the core import's snapshot) can still reach on every target.
typealias AppFriend = Friend

/// A friend as 3.1.1 stored it. The class keeps its name and every stored
/// property: SwiftData finds existing rows by them.
@Model
final class Friend {
    var username: String
    /// The contact's client id; empty for an invite sent to a handle.
    var peerID: String = ""
    var convoTopicID: String?
    var handshakeTopicID: String?
    /// The identity key, 7237 bytes once pinned.
    var publicKey: Data
    var isOnline: Bool
    var inviteStatusRaw: String?
    var keyVerified: Bool?
    var vanishedAt: Date?
    var blockedAt: Date?

    @Relationship(deleteRule: .cascade) var messages: [Message]?
    var profile: Profile?

    init(username: String, peerID: String = "", publicKey: Data = Data(), profile: Profile? = nil) {
        self.username = username
        self.peerID = peerID
        self.publicKey = publicKey
        self.isOnline = false
        self.messages = []
        self.profile = profile
    }

    var isPending: Bool { peerID.isEmpty }
    var isAccepted: Bool { inviteStatusRaw == "accepted" }
    var isInviteSent: Bool { inviteStatusRaw == "invite_sent" }

    // MARK: - The ratchet session, in the Keychain

    /// Keychain account for this friend's session: namespaced by the owning
    /// profile, since two profiles talking to one person hold two sessions.
    static func ratchetAccount(profileID: UUID?, peerID: String) -> String {
        "aes.\(profileID?.uuidString ?? "noprofile").\(peerID).ratchet"
    }

    /// The double-ratchet session with this friend, read under the unlock.
    /// State at another protocol version had already been discarded by 3.1.1.
    var ratchetSession: RatchetSessionState? {
        guard let data = AESKeyStore.read(Self.ratchetAccount(profileID: profile?.id, peerID: peerID)).data,
              let session = try? JSONDecoder().decode(RatchetSessionState.self, from: data),
              session.v == RatchetSessionState.protocolVersion
        else { return nil }
        return session
    }

    /// Removes this friend's session from the Keychain.
    func clearSession() {
        AESKeyStore.delete(Self.ratchetAccount(profileID: profile?.id, peerID: peerID))
    }
}

// MARK: - The 3.1.1 ratchet state, as it was JSON-encoded

struct RatchetChain: Codable, Equatable {
    var ck: Data
    var n: Int
}

struct SkippedMessageKey: Codable, Equatable {
    var chain: String
    var n: Int
    var key: Data
}

struct RatchetInitHeader: Codable, Equatable {
    var ctId: Data
    var ctMt: Data
    var ctOt: Data?
    var otId: Int?
    var rk: Data
    var cid: String
}

struct RatchetSessionState: Codable, Equatable {
    static let protocolVersion = 2

    var v: Int = RatchetSessionState.protocolVersion
    var root: Data
    var rkPub: Data
    var rkSec: Data
    var peerRkPub: Data?
    var send: RatchetChain?
    var recv: RatchetChain?
    var prevSendN: Int
    var skipped: [SkippedMessageKey]
    var seenChains: [String]
    var pendingInit: RatchetInitHeader?
    var sentOnChain: Int
    var chainStartedAt: Date
}

/// The 3.1.1 prekey secrets, JSON-encoded in the Keychain.
struct PrekeyStore: Codable {
    var mediumPk: Data
    var mediumSk: Data
    var oneTime: [String: PrekeyPair]
    var nextId: Int
    var rotatedAt: Date

    struct PrekeyPair: Codable {
        var pk: Data
        var sk: Data
    }

    static func account(for profileID: UUID?) -> String {
        "prekeys.\(profileID?.uuidString ?? "noprofile")"
    }
}
