// The Chats tab: conversations only. Contacts and invites live in their own
// tab, so this list stops mixing three jobs into one screen.

#if os(iOS)
import SwiftUI

struct ChatListView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var chat: ChatStore

    let profileManager: ProfileManager?

    /// Navigation path, so a demo or screenshot run can open a conversation
    /// without a tap.
    @State private var path = NavigationPath()
    @State private var appError: AppError?

    /// Only established contacts get a conversation. Pending invites can't be
    /// messaged — they have no secure channel yet — so showing them here would
    /// just be a row that fails when tapped.
    private var conversations: [Contact] {
        chat.contacts
            .filter { $0.inviteStatus == .accepted }
            // Most recently active first. Alphabetical is right for a contact
            // list and wrong for a conversation list — the thread you just
            // replied to should not be three screens down because of its name.
            .sorted { lastActivity($0) > lastActivity($1) }
    }

    /// When this conversation last moved. Never-used threads sort to the bottom
    /// but keep a stable order among themselves.
    private func lastActivity(_ friend: Contact) -> Date {
        friend.lastMessage?.timestamp ?? .distantPast
    }

    var body: some View {
        NavigationStack(path: $path) {
            VStack(spacing: 0) {
                HQScreenHeader(path: "chats", appState: appState, profileManager: profileManager)

                if conversations.isEmpty {
                    HQEmptyState(
                        title: "no conversations yet",
                        message: "add someone in Contacts to start messaging securely"
                    )
                    .frame(maxHeight: .infinity)
                } else {
                    List(conversations) { friend in
                        NavigationLink(value: friend) {
                            ContactRow(friend: friend, style: .conversation)
                        }
                        .listRowBackground(Color.clear)
                        .padding(.vertical, 4)
                    }
                    .scrollContentBackground(.hidden)
                    .refreshable { chat.refresh() }
                }
            }
            .background(HQScreenBackground())
            // The prompt header names the screen; a system title on top of it
            // would say it twice, in a different voice.
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: Contact.self) { friend in
                ChatView(peer: friend.peerID, profileManager: profileManager)
            }
            .hqError($appError)
            .onAppear {
                // Demo: deep-link straight into a conversation to showcase chat.
                if PersistenceController.isDemo, path.isEmpty,
                   ProcessInfo.processInfo.environment["DEMO_CHAT"] == "1",
                   let friend = conversations.first(where: { $0.lastMessage != nil })
                        ?? conversations.first {
                    path.append(friend)
                }
            }
            // One prompt, here, for every preview on the list. Asking from a
            // screen's `task` rather than from a row keeps authentication off
            // the render path entirely.
            .task { await chat.unlock() }
        }
    }
}
#endif
