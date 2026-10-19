// Local notifications and unread counts: the foreground presentation rule for
// pushes, and the local notification raised when a message or invite arrives
// over the live connection.
//
// Bodies are content-free, like the push bridge's: the sender's name and a
// fixed string, never message text, which would escape the at-rest sealing.

import Foundation
import UserNotifications

@MainActor
final class NotificationService: NSObject, ObservableObject {
    static let shared = NotificationService()

    /// The username of the conversation on screen. Messages from this friend
    /// don't raise a banner — the user is already looking at them.
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

    /// Nil outside an app bundle (a test binary), where asking for it traps.
    private var center: UNUserNotificationCenter? {
        Bundle.main.bundleIdentifier == nil ? nil : .current()
    }

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
        center?.add(request)
    }

    // MARK: - Counts

    /// The active profile's unread messages (the core counts frames still
    /// waiting for an unlock too) and pending invites, for the tab badges and
    /// the app icon.
    func setCounts(unreadMessages: Int, pendingInvites: Int) {
        guard unreadMessages != self.unreadMessages || pendingInvites != self.pendingInvites else { return }
        self.unreadMessages = unreadMessages
        self.pendingInvites = pendingInvites
        setBadge(unreadMessages + pendingInvites)
    }

    private func setBadge(_ count: Int) {
        center?.setBadgeCount(count)
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
