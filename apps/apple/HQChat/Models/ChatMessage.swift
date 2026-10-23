import Foundation
import HQChatCore

/// One message as the screens show it. The core stores it sealed; this copy
/// lives in memory while a conversation or its preview is on screen.
struct ChatMessage: Identifiable, Hashable {
    enum DeliveryStatus: Hashable {
        case sending   // sealing, or waiting for the link
        case sent      // the broker took it
        case delivered // the recipient's receipt arrived
        case queued    // recipient offline; the broker holds it
        case failed    // never left this device; retryable
    }

    /// The message id, shared by both sides.
    var id: String
    /// The friend the conversation is with.
    var peer: String
    var isOutgoing: Bool
    var content: String
    var timestamp: Date
    /// Where an outgoing message has got to; `.sent` for received ones.
    var deliveryStatus: DeliveryStatus
}

extension ChatMessage {
    init(_ m: HQChatCore.Message) {
        self.init(id: m.msgId, peer: m.peer, isOutgoing: m.outgoing, content: m.text,
                  timestamp: Date(milliseconds: m.at),
                  deliveryStatus: m.delivery.map(DeliveryStatus.init) ?? .sent)
    }
}

extension ChatMessage.DeliveryStatus {
    init(_ d: Delivery) {
        switch d {
        case .sending: self = .sending
        case .queued: self = .queued
        case .sent: self = .sent
        case .delivered: self = .delivered
        case .failed: self = .failed
        }
    }
}
