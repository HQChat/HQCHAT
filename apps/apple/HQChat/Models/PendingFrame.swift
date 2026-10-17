import Foundation
import SwiftData

/// An inbound frame admitted but not yet opened: ratchet ciphertext exactly as
/// it arrived.
///
/// Opening needs the ratchet session, which needs the user. So a frame that
/// arrives while the app is locked (or a backlog the broker replays on
/// reconnect) is stored here, notified as "an encrypted message", and opened
/// once the user unlocks. It holds nothing the broker did not already see.
@Model
final class PendingFrame {
    enum Kind: String {
        case initiate = "init"
        case message = "msg"
        case receipt
        /// A challenge or proof on the friendship's handshake topic.
        case handshake
    }

    var profileID: UUID?
    /// The sender's client id; frames are opened per sender, in arrival order.
    var senderID: String = ""
    var topic: String = ""
    /// The wire bytes. The AAD is re-derived from them when the frame is opened.
    var raw: Data = Data()
    var kindRaw: String = Kind.message.rawValue
    /// Identifies a re-delivery of the same frame, which is not admitted twice.
    var dedupeKey: String = ""
    var receivedAt: Date = Date()
    /// Arrival order, which is the order the ratchet must see.
    var seq: Int = 0

    var kind: Kind { Kind(rawValue: kindRaw) ?? .message }

    /// Whether the frame can carry a message the user has not read.
    var carriesMessage: Bool { kind == .initiate || kind == .message }

    init(profileID: UUID?, senderID: String, topic: String, raw: Data,
         kind: Kind, dedupeKey: String, seq: Int) {
        self.profileID = profileID
        self.senderID = senderID
        self.topic = topic
        self.raw = raw
        self.kindRaw = kind.rawValue
        self.dedupeKey = dedupeKey
        self.receivedAt = Date()
        self.seq = seq
    }
}
