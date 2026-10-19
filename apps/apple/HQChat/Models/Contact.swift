import Foundation
import HQChatCore

/// A person as the screens show them: a friend, a friend request either way,
/// or an identity kept read-only (blocked, or replaced by a new key). Built
/// from the core's friend list, invites and sent requests; the core holds the
/// state, this is only what to draw.
struct Contact: Identifiable, Hashable {
    enum InviteStatus: Hashable {
        /// A friend: a conversation exists or can start.
        case accepted
        /// This user asked; they have not answered.
        case inviteSent
        /// They asked; this user has not answered.
        case inviteReceived
    }

    /// The contact's client id, `sha256(lowercase-hex(publicKey))`. Empty for
    /// a request sent to a username the server has not resolved for us.
    var peerID: String
    var username: String
    var inviteStatus: InviteStatus
    var isOnline = false
    var hasSession = false
    /// Their identity key is pinned (checked against their id).
    var hasPinnedKey = false
    /// The user compared the safety number with them.
    var isKeyVerified = false
    /// When the user blocked them: the conversation is kept, read-only.
    var blockedAt: Date?
    /// When their username moved to another identity: kept, read-only.
    var vanishedAt: Date?
    /// Received messages not read yet, including those waiting for an unlock.
    var unread = 0
    /// The newest message either way, for the conversation list.
    var lastMessage: ChatMessage?

    var id: String { peerID.isEmpty ? "to:\(username)" : peerID }

    var isVanished: Bool { vanishedAt != nil }
    var isBlocked: Bool { blockedAt != nil }
    /// Nothing can be sent to this contact, whichever of the two reasons applies.
    var isReadOnly: Bool { isVanished || isBlocked }
    /// A request sent to a handle, not yet tied to an id.
    var isPending: Bool { peerID.isEmpty }
    /// Ready but never written to: the session opens with the first message.
    var isReadyButUnopened: Bool { !hasSession && hasPinnedKey && !isVanished && lastMessage == nil }
}

extension Contact {
    /// A friend from the core.
    init(_ f: FriendView, lastMessage: ChatMessage?) {
        self.init(
            peerID: f.id,
            username: f.username ?? String(f.id.prefix(8)),
            inviteStatus: .accepted,
            isOnline: f.online,
            hasSession: f.hasSession,
            hasPinnedKey: f.hasKey,
            isKeyVerified: f.verified,
            blockedAt: f.blockedAt.map(Date.init(milliseconds:)),
            vanishedAt: f.vanishedAt.map(Date.init(milliseconds:)),
            unread: Int(f.unread),
            lastMessage: lastMessage
        )
    }

    /// A request waiting for this user's answer.
    init(_ i: InviteView) {
        self.init(peerID: i.id, username: i.username.isEmpty ? String(i.id.prefix(8)) : i.username,
                  inviteStatus: .inviteReceived)
    }

    /// A request this user sent, to a username or an id.
    init(_ s: SentInviteView) {
        let isID = s.to.count == 64 && s.to.allSatisfy(\.isHexDigit)
        self.init(peerID: isID ? s.to.lowercased() : "", username: isID ? String(s.to.prefix(8)) : s.to,
                  inviteStatus: .inviteSent)
    }
}

extension Date {
    init(milliseconds: Int64) {
        self.init(timeIntervalSince1970: TimeInterval(milliseconds) / 1000)
    }

    var milliseconds: Int64 { Int64((timeIntervalSince1970 * 1000).rounded()) }
}
