// TRANSITION CODE (see CoreImport.swift): the 3.1.1 message row, kept only so
// the move to the core can read it and then delete it. Nothing else uses it.

import CryptoKit
import Foundation
import SwiftData

/// The 3.1.1 message model, by a name that files importing the core (whose
/// bindings also declare a `Message`) can use unambiguously.
typealias AppMessage = Message

/// A message as 3.1.1 stored it. The class keeps its name and every stored
/// property: SwiftData finds existing rows by them.
@Model
final class Message {
    /// The body, sealed with the profile's message key (`MessageKeyStore`).
    private var contentCipher: Data?
    var timestamp: Date
    var isOutgoing: Bool
    var friend: Friend?
    var profileID: UUID?
    /// When the user saw it; incoming and nil is unread.
    var readAt: Date?
    var messageId: String?
    var deliveryStatusRaw: String?

    init(timestamp: Date, isOutgoing: Bool, friend: Friend?, profileID: UUID?) {
        self.timestamp = timestamp
        self.isOutgoing = isOutgoing
        self.friend = friend
        self.profileID = profileID
    }

    enum DeliveryStatus: String, Codable {
        case sending, sent, delivered, queued, failed
    }

    var deliveryStatus: DeliveryStatus {
        DeliveryStatus(rawValue: deliveryStatusRaw ?? "") ?? .sent
    }

    var isUnread: Bool { !isOutgoing && readAt == nil }

    /// The body for the move: the plaintext, or nil when this row cannot be
    /// opened (its key is gone). Never a placeholder, so nothing like
    /// "locked" is ever written into the new history as if it had been said.
    var contentForImport: String? {
        guard let contentCipher else { return "" }
        return Self.open(contentCipher, profileID: profileID)
    }

    /// The v2 envelope: a per-message key wrapped to the profile's Enclave
    /// key, then AES-GCM. Opens with the read context the unlock holds.
    private static func open(_ cipher: Data, profileID: UUID?) -> String? {
        guard let profileID, MessageKeyStore.hasKey(for: profileID),
              cipher.first == 2, cipher.count > 3 else { return nil }
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
}
