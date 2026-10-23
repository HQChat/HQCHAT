// TRANSITION CODE (see CoreImport.swift): the 3.1.1 row for a frame received
// while locked, kept only so the move to the core can carry it over unopened.

import Foundation
import SwiftData

/// A frame 3.1.1 admitted but had not opened: ciphertext as it arrived. The
/// class keeps its name and every stored property: SwiftData finds existing
/// rows by them.
@Model
final class PendingFrame {
    var profileID: UUID?
    var senderID: String = ""
    var topic: String = ""
    var raw: Data = Data()
    var kindRaw: String = "msg"
    var dedupeKey: String = ""
    var receivedAt: Date = Date()
    /// Arrival order, which is the order the ratchet must see.
    var seq: Int = 0

    init(profileID: UUID?, topic: String, raw: Data, seq: Int) {
        self.profileID = profileID
        self.topic = topic
        self.raw = raw
        self.seq = seq
    }
}
