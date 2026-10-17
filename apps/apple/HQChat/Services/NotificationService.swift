// Local notifications and unread counts: the foreground presentation rule for
// pushes, and the local notification raised when a message or invite arrives
// over the live connection.
//
// Bodies are content-free, like the push bridge's: the sender's name and a
// fixed string, never message text, which would escape the at-rest sealing.

import Foundation
import SwiftData
import UserNotifications

@MainActor
final class NotificationService: NSObject, ObservableObject {
    static let shared = NotificationService()

    /// The conversation currently on screen. Messages from this friend don't
    /// raise a banner — the user is already looking at them.
    var visibleConversation: String?

    /// Whether the app is actually in front. `visibleConversation` outlives
    /// backgrounding (the view stays mounted), so without this, leaving the app
    /// while a conversation was open silently suppressed that conversation's
    /// notifications — the one case where you most want them.
    var isForeground = true

    /// Unread messages + pending invites, published for the tab badges.
    @Published private(set) var unreadMessages = 0
    @Published private(set) var pendingInvites = 0

    private override init() { super.init() }

    // MARK: - Raising notifications

    func notifyMessage(from sender: String) {
        guard !(isForeground && sender == visibleConversation) else { return }
        post(id: "msg.\(sender).\(UUID().uuidString)",
             title: sender,
             body: "Sent you an encrypted message")
    }

    func notifyInvite(from sender: String) {
        post(id: "invite.\(sender)",
             title: "Friend request",
             body: "\(sender) wants to connect")
    }

    private func post(id: String, title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(identifier: id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    // MARK: - Counts

    /// Recount unread messages and pending invites for one profile, and push
    /// the total to the app icon. Cheap enough to call after every arrival.
    func refreshCounts(modelContext: ModelContext, profileID: UUID?) {
        guard let profileID else {
            unreadMessages = 0
            pendingInvites = 0
            setBadge(0)
            return
        }

        let unreadDescriptor = FetchDescriptor<Message>(
            predicate: #Predicate<Message> { message in
                message.profileID == profileID && !message.isOutgoing && message.readAt == nil
            }
        )
        // Frames not opened yet count too: each was notified when it arrived.
        unreadMessages = ((try? modelContext.fetchCount(unreadDescriptor)) ?? 0)
            + InboundQueue.unopenedMessageCount(modelContext: modelContext, profileID: profileID)

        let received = Friend.InviteStatus.inviteReceived.rawValue
        let inviteDescriptor = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { friend in
                friend.profile?.id == profileID && friend.inviteStatusRaw == received
            }
        )
        pendingInvites = (try? modelContext.fetchCount(inviteDescriptor)) ?? 0

        setBadge(unreadMessages + pendingInvites)
    }

    /// Mark a conversation read and refresh the badges.
    func markRead(friend: Friend, modelContext: ModelContext) {
        let unread = (friend.messages ?? []).filter { $0.isUnread }
        guard !unread.isEmpty else { return }
        let now = Date()
        for message in unread { message.readAt = now }
        try? modelContext.save()
        refreshCounts(modelContext: modelContext, profileID: friend.profile?.id)
    }

    private func setBadge(_ count: Int) {
        UNUserNotificationCenter.current().setBadgeCount(count)
    }
}

// MARK: - Foreground presentation

extension NotificationService: UNUserNotificationCenterDelegate {
    /// Shows notifications while the app is open, except for the conversation
    /// on screen. Local notifications carry the sender as their title; a server
    /// push carries a fixed, content-free title and is only sent while the
    /// server believes the device is offline.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        let title = notification.request.content.title
        if await isViewing(title) { return [] }
        return [.banner, .sound, .badge]
    }

    /// Whether `sender` is the conversation currently on screen.
    private func isViewing(_ sender: String) -> Bool {
        isForeground && sender == visibleConversation
    }
}
