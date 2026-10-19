// TRANSITION CODE: it exists only for the update from 3.1.1, the last build on
// the Swift implementation, to the first build on the core. It is deleted,
// with everything under Migration/, a few weeks after that release; a profile
// not opened in that window starts fresh (docs/architecture/core-wiring.md).

import Foundation
import HQChatCore
import SwiftData

/// The move from the Swift implementation to the core, once per profile.
///
/// Everything the profile holds is read into a `LegacySnapshot` (plain values,
/// under the user's unlock), mapped here into the core's `ImportData`, and
/// handed to `Engine.importState`, which checks all of it before writing
/// anything. The old items are left where they are: they are removed only
/// after the core has opened the profile, so a failed or interrupted move
/// loses nothing and can simply run again.
struct LegacySnapshot {
    struct Friend {
        var peerID: String
        var username: String?
        /// The pinned identity key; anything but a full key is not pinned.
        var publicKey: Data
        var convoTopicID: String?
        var handshakeTopicID: String?
        var session: RatchetSessionState?
        var blockedAt: Date?
        var vanishedAt: Date?
    }

    struct Message {
        var peerID: String
        var messageID: String
        var isOutgoing: Bool
        var text: String
        var timestamp: Date
        var status: AppMessage.DeliveryStatus?
        /// A received message the user has seen.
        var read: Bool
    }

    struct Pending {
        var topic: String
        var raw: Data
        var receivedAt: Date
    }

    var identityPublicKey: Data
    var identitySecretKey: Data
    var prekeys: PrekeyStore?
    var friends: [Friend]
    var messages: [Message]
    var pending: [Pending]
}

enum CoreImportError: Error, Equatable {
    /// A counter or id that does not fit the core's (negative, or past u32).
    case outOfRange(String)
    /// A chain id that is not 16 bytes of hex.
    case badChainID(String)
}

enum CoreImport {
    /// The snapshot as the core's import. Pure: every conversion is here.
    static func importData(from s: LegacySnapshot) throws -> ImportData {
        ImportData(
            identityPublicKey: s.identityPublicKey,
            identitySecretKey: s.identitySecretKey,
            prekeys: try s.prekeys.map(prekeys),
            peers: try s.friends.filter { !$0.peerID.isEmpty }.map(peer),
            messages: s.messages.map(message),
            pending: s.pending.map {
                ImportPendingData(topic: $0.topic, payload: $0.raw, at: milliseconds($0.receivedAt))
            }
        )
    }

    static func milliseconds(_ date: Date) -> Int64 {
        Int64((date.timeIntervalSince1970 * 1000).rounded())
    }

    private static func u32(_ value: Int, _ what: String) throws -> UInt32 {
        guard let v = UInt32(exactly: value) else { throw CoreImportError.outOfRange(what) }
        return v
    }

    private static func chainID(_ hex: String) throws -> Data {
        guard let data = Data(hexString: hex), data.count == 16 else { throw CoreImportError.badChainID(hex) }
        return data
    }

    private static func prekeys(_ p: PrekeyStore) throws -> ImportPrekeysData {
        ImportPrekeysData(
            mediumPublicKey: p.mediumPk,
            mediumSecretKey: p.mediumSk,
            rotatedAt: milliseconds(p.rotatedAt),
            oneTime: try p.oneTime.sorted { $0.key < $1.key }.map { id, pair in
                guard let n = Int(id) else { throw CoreImportError.outOfRange("one-time prekey id \(id)") }
                return ImportOneTimeKey(id: try u32(n, "one-time prekey id"), secretKey: pair.sk)
            },
            nextId: try u32(p.nextId, "next prekey id")
        )
    }

    private static func peer(_ f: LegacySnapshot.Friend) throws -> ImportPeerData {
        ImportPeerData(
            id: f.peerID,
            username: f.username,
            convoId: f.convoTopicID,
            handshakeId: f.handshakeTopicID,
            pinnedPublicKey: f.publicKey.count == HQCPublicKeySize ? f.publicKey : nil,
            session: try f.session.map(session),
            blockedAt: f.blockedAt.map(milliseconds),
            vanishedAt: f.vanishedAt.map(milliseconds)
        )
    }

    private static func session(_ s: RatchetSessionState) throws -> ImportSessionData {
        ImportSessionData(
            root: s.root,
            ratchetPublicKey: s.rkPub,
            ratchetSecretKey: s.rkSec,
            peerRatchetPublicKey: s.peerRkPub,
            send: try s.send.map { ImportChain(key: $0.ck, n: try u32($0.n, "sending chain index")) },
            recv: try s.recv.map { ImportChain(key: $0.ck, n: try u32($0.n, "receiving chain index")) },
            previousSendCount: try u32(s.prevSendN, "previous chain length"),
            skipped: try s.skipped.map {
                ImportSkippedKey(chain: try chainID($0.chain), n: try u32($0.n, "skipped key index"), key: $0.key)
            },
            pendingInit: try s.pendingInit.map { i in
                ImportInit(
                    ctId: i.ctId,
                    ctMt: i.ctMt,
                    ctOt: i.ctOt,
                    oneTimeId: try i.otId.map { try u32($0, "one-time prekey id") },
                    ratchetPublicKey: i.rk,
                    chain: try chainID(i.cid)
                )
            },
            seenChains: try s.seenChains.map(chainID),
            sentOnChain: try u32(s.sentOnChain, "messages on the chain"),
            chainStartedAt: milliseconds(s.chainStartedAt)
        )
    }

    private static func message(_ m: LegacySnapshot.Message) -> ImportMessageData {
        ImportMessageData(
            peer: m.peerID,
            msgId: m.messageID,
            outgoing: m.isOutgoing,
            text: m.text,
            at: milliseconds(m.timestamp),
            delivery: m.isOutgoing ? m.status.map(delivery) : nil,
            read: m.isOutgoing || m.read
        )
    }

    private static func delivery(_ s: AppMessage.DeliveryStatus) -> Delivery {
        switch s {
        case .sending: return .sending
        case .sent: return .sent
        case .delivered: return .delivered
        case .queued: return .queued
        case .failed: return .failed
        }
    }
}

// MARK: - Reading the profile

extension LegacySnapshot {
    enum ReadError: Error, Equatable {
        /// The stores are locked: the move runs only after the user unlocks.
        case locked
        /// The profile's prekey record exists but does not decode.
        case unreadablePrekeys
    }

    /// Reads everything `profile` holds into a snapshot. Runs on the main actor
    /// with the stores unlocked; `secretKey` is the identity key the caller
    /// read through `ProfileManager` under that unlock. Rows whose key is gone
    /// for good (already shown as unreadable) are left out and counted.
    @MainActor
    static func read(profile: Profile, secretKey: Data, context: ModelContext) throws -> (LegacySnapshot, unreadable: Int) {
        guard AESKeyStore.isUnlocked(), MessageKeyStore.canRead else { throw ReadError.locked }

        let prekeys: PrekeyStore?
        switch AESKeyStore.read(PrekeyService.account(for: profile.id)) {
        case let .value(data):
            guard let store = try? JSONDecoder().decode(PrekeyStore.self, from: data) else {
                throw ReadError.unreadablePrekeys
            }
            prekeys = store
        case .absent:
            prekeys = nil
        case .locked:
            throw ReadError.locked
        }

        let friendRows = try context.fetch(FetchDescriptor<AppFriend>())
            .filter { $0.profile?.id == profile.id }
        let friends = friendRows.map { f in
            Friend(peerID: f.peerID, username: f.username, publicKey: f.publicKey,
                   convoTopicID: f.convoTopicID, handshakeTopicID: f.handshakeTopicID,
                   session: f.ratchetSession, blockedAt: f.blockedAt, vanishedAt: f.vanishedAt)
        }

        let id = profile.id
        let messageRows = try context.fetch(FetchDescriptor<AppMessage>(
            predicate: #Predicate { $0.profileID == id },
            sortBy: [SortDescriptor(\.timestamp)]
        ))
        var unreadable = 0
        var messages: [Message] = []
        for row in messageRows {
            guard let peer = row.friend?.peerID, !peer.isEmpty else { continue }
            guard let text = row.contentForImport else {
                unreadable += 1
                continue
            }
            messages.append(Message(
                peerID: peer,
                // Rows from before message ids were kept get one now: the core
                // needs an id, and nothing outside this device refers to them.
                messageID: row.messageId ?? "legacy-\(UUID().uuidString.lowercased())",
                isOutgoing: row.isOutgoing,
                text: text,
                timestamp: row.timestamp,
                status: row.isOutgoing ? row.deliveryStatus : nil,
                read: !row.isUnread
            ))
        }

        let pendingRows = try context.fetch(FetchDescriptor<PendingFrame>(
            predicate: #Predicate { $0.profileID == id },
            sortBy: [SortDescriptor(\.seq)]
        ))
        let pending = pendingRows.map { Pending(topic: $0.topic, raw: $0.raw, receivedAt: $0.receivedAt) }

        let snapshot = LegacySnapshot(
            identityPublicKey: profile.publicKey ?? Data(),
            identitySecretKey: secretKey,
            prekeys: prekeys,
            friends: friends,
            messages: messages,
            pending: pending
        )
        return (snapshot, unreadable)
    }
}
