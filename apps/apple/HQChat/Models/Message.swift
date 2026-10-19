import Foundation
import SwiftData
import CryptoKit

/// The app's message model, by a name that files importing the core (whose
/// bindings also declare a `Message`) can use unambiguously on every target.
typealias AppMessage = Message

@Model
final class Message {
    /// The message body, sealed with the owning profile's message key (`MessageKeyStore`).
    private var contentCipher: Data?

    var timestamp: Date
    var isOutgoing: Bool
    var friend: Friend?

    /// The profile this message belongs to. Denormalised from
    /// `friend?.profile?.id` because a `#Predicate` cannot walk two levels of
    /// optional relationship — and because system messages have no friend at
    /// all. It also selects the at-rest key, so the same profile that wrote a
    /// message is the only one that can read it back.
    var profileID: UUID?

    /// When the local user saw this message. Incoming + nil = unread, which is
    /// what drives the tab, row, and app-icon badges.
    var readAt: Date?

    /// Client-generated id that correlates delivery receipts.
    var messageId: String?
    /// Delivery state for outgoing messages (optional raw for migration safety).
    var deliveryStatusRaw: String?

    /// Decrypted body, cached for the lifetime of this object. `@Transient` is
    /// never persisted, so the plaintext exists only in memory.
    @Transient private var plaintextCache: String?

    /// Shown in place of a body we hold ciphertext for but cannot open — a row
    /// belonging to a profile whose key is gone (deleted profile, restored
    /// backup). Better than crashing or silently showing an empty bubble.
    static let unreadableBody = "[encrypted — key unavailable]"

    /// The message body in the clear. Reading opens the sealed box; writing
    /// re-seals it. Callers see a plain `String` and never touch key material.
    var content: String {
        get {
            if let plaintextCache { return plaintextCache }
            let text: String
            if let contentCipher {
                guard let opened = Self.open(contentCipher, profileID: profileID) else {
                    // Two failures share the same nil, and only one is permanent.
                    //
                    // Temporary: a sealed row we cannot open because nothing has unlocked the
                    // store yet; it must not be cached as unreadable.
                    //
                    // Permanent: the key is not ours (another profile's row, or a lost key).
                    //
                    // `canRead` is false in any unauthenticated process, so the seal version
                    // decides too: only a row sealed behind the `.userPresence` key can be
                    // waiting on an unlock.
                    let awaitingUnlock = contentCipher.first == Self.sealVersion
                        && !MessageKeyStore.canRead
                    return awaitingUnlock ? Self.lockedBody : cacheUnreadable()
                }
                text = opened
            } else {
                text = ""
            }
            plaintextCache = text
            return text
        }
        set {
            plaintextCache = newValue
            guard let sealed = Self.seal(newValue, profileID: profileID) else {
                // Never persist plaintext: the text stays in memory for this
                // session only, and the row reads as unreadable after a reload.
                contentCipher = nil
                Log.storage.error("[Message] ❌ could not seal a body — nothing persisted. No Secure Enclave key for this profile?")
                return
            }
            contentCipher = sealed
        }
    }

    /// The body for the move to the core: the plaintext, or nil when this row
    /// cannot be opened now. Never a placeholder, so nothing like "locked" is
    /// ever written into the new history as if it had been said.
    var contentForImport: String? {
        guard let contentCipher else { return "" }
        return Self.open(contentCipher, profileID: profileID)
    }

    /// Cache and return the permanent "cannot be read" body.
    private func cacheUnreadable() -> String {
        plaintextCache = Self.unreadableBody
        return Self.unreadableBody
    }

    enum DeliveryStatus: String, Codable {
        case sending   // not yet acknowledged by server
        case sent      // server received it
        case delivered // recipient's client received it
        case queued    // recipient offline; stored server-side
        case failed    // never left this device; retryable

        /// `queued` is about the *recipient* being offline. `failed` is about
        /// us: the send threw, so nothing reached the server at all.
        var isTerminalFailure: Bool { self == .failed }

        /// How far along the delivery path this state is. `failed` sits with
        /// `sent`: a send that threw can still overwrite an optimistic local
        /// state, but never a receipt the server actually sent us.
        var rank: Int {
            switch self {
            case .sending:   return 0
            case .sent:      return 1
            case .failed:    return 1
            case .queued:    return 2
            case .delivered: return 3
            }
        }
    }

    var deliveryStatus: DeliveryStatus {
        get { DeliveryStatus(rawValue: deliveryStatusRaw ?? "") ?? .sent }
        set { deliveryStatusRaw = newValue.rawValue }
    }

    /// Move delivery state forward only.
    ///
    /// The sender writes `.sent` when its own `send` call returns, while the
    /// server's `message_delivered` receipt arrives on the socket independently —
    /// and on a fast connection the receipt usually wins the race. Assigning
    /// `deliveryStatus` directly then knocked a delivered message back to
    /// "sent", which is why the checkmarks looked unreliable and differed
    /// between devices. Use this everywhere instead of the raw setter.
    func advanceDelivery(to status: DeliveryStatus) {
        guard status.rank >= deliveryStatus.rank else { return }
        deliveryStatus = status
    }

    /// True for an incoming message the user hasn't opened yet.
    var isUnread: Bool { !isOutgoing && readAt == nil }

    init(content: String, timestamp: Date = Date(), isOutgoing: Bool, friend: Friend? = nil,
         messageId: String? = nil, deliveryStatus: DeliveryStatus = .sent,
         profileID: UUID? = nil, readAt: Date? = nil) {
        self.timestamp = timestamp
        self.isOutgoing = isOutgoing
        self.friend = friend
        self.messageId = messageId
        self.deliveryStatusRaw = deliveryStatus.rawValue
        // Our own messages are read by definition.
        self.readAt = readAt ?? (isOutgoing ? timestamp : nil)
        // Must precede `content =`: the setter needs a key to seal against.
        self.profileID = profileID ?? friend?.profile?.id
        self.content = content
    }

    // MARK: - At-rest sealing

    /// Envelope version byte. v2 is the hybrid scheme: a per-message key
    /// wrapped to the profile's public key, so sealing needs no user and opening
    /// does. It is now the ONLY scheme — a row with no version byte came from the
    /// symmetric floor, which has been removed along with the key that opened it,
    /// and there is no installed base holding one.
    private static let sealVersion: UInt8 = 2

    /// Shown while the OS is refusing authentication. Deliberately not the same
    /// as `unreadableBody`: this row is fine, and will render on the next read.
    static let lockedBody = "🔒 locked"


    private static func seal(_ text: String, profileID: UUID?) -> Data? {
        guard let profileID, let data = text.data(using: .utf8) else { return nil }
        // Fresh key per message: the wrap is what carries the protection, and a
        // per-message key means one unwrap never yields another row.
        let messageKey = SymmetricKey(size: .bits256)
        // No fallback: if the hybrid wrap cannot be made, nothing is sealed and
        // nothing is stored (see the `content` setter). A key without user
        // authentication would quietly become the at-rest key on every device
        // without a Secure Enclave.
        guard let wrapped = MessageKeyStore.wrap(messageKey, for: profileID),
              wrapped.count <= Int(UInt16.max),
              let body = try? AES.GCM.seal(data, using: messageKey).combined else {
            return nil
        }

        var out = Data([sealVersion])
        out.append(UInt8(wrapped.count >> 8))
        out.append(UInt8(wrapped.count & 0xFF))
        out.append(wrapped)
        out.append(body)
        return out
    }

    /// Opens a v2 envelope (prompts, unless an authenticated context is already
    /// live) or a legacy one. Never mints a key: a missing key means this row
    /// belongs to a profile that is gone, and it must stay unreadable.
    private static func open(_ cipher: Data, profileID: UUID?) -> String? {
        guard let profileID, MessageKeyStore.hasKey(for: profileID) else { return nil }

        if cipher.first == sealVersion, cipher.count > 3 {
            let base = cipher.startIndex
            let wrappedLen = Int(cipher[base + 1]) << 8 | Int(cipher[base + 2])
            let wrappedEnd = base + 3 + wrappedLen
            guard cipher.count >= 3 + wrappedLen else { return nil }
            let wrapped = Data(cipher[(base + 3)..<wrappedEnd])
            guard let messageKey = MessageKeyStore.unwrap(wrapped, for: profileID),
                  let box = try? AES.GCM.SealedBox(combined: Data(cipher[wrappedEnd...])),
                  let data = try? AES.GCM.open(box, using: messageKey) else { return nil }
            return String(data: data, encoding: .utf8)
        }

        // Anything else has no key that opens it without the user: unreadable.
        return nil
    }
}
