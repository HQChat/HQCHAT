// iPhone shell: a bottom tab bar replacing the old "…" toolbar menu.
//
// macOS keeps `FriendListView`'s NavigationSplitView + profile rail — a tab bar
// is the wrong shape for a desktop window, and the split view is right there.

#if os(iOS)
import SwiftUI

struct RootTabView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var chat: ChatStore

    let profileManager: ProfileManager?

    @ObservedObject private var notifications = NotificationService.shared

    /// The selection lives on `AppState` (as `AppTab`), not here: the
    /// "username taken" banner that switches to Settings sits at the root now,
    /// above this view, and cannot reach `@State` declared inside it.
    private var tab: Binding<AppTab> { $appState.selectedTab }

    var body: some View {
        TabView(selection: tab) {
            ChatListView(profileManager: profileManager)
            .tabItem { Label("chats", systemImage: "bubble.left.and.bubble.right.fill") }
            .badge(notifications.unreadMessages)
            .tag(AppTab.chats)

            ContactsView(profileManager: profileManager)
            .tabItem { Label("contacts", systemImage: "person.2.fill") }
            .badge(notifications.pendingInvites)
            .tag(AppTab.contacts)

            SettingsView(profileManager: profileManager, isEmbedded: true)
                .tabItem { Label("settings", systemImage: "gearshape.fill") }
                .tag(AppTab.settings)
        }
        .tint(HQColor.green)
        // Swipe left/right between the three tabs. The tab bar is still the
        // primary control; this just means a thumb already resting on the
        // content doesn't have to travel to the bottom of the screen.
        .hqSwipeNavigation(onBack: { move(-1) }, onForward: { move(1) })
        .onAppear { chat.refresh() }
    }

    /// Step `delta` tabs along, stopping at the ends rather than wrapping —
    /// wrapping from settings back to chats would make the gesture feel like it
    /// had lost its place.
    private func move(_ delta: Int) {
        guard let i = AppTab.ordered.firstIndex(of: appState.selectedTab) else { return }
        let next = i + delta
        guard AppTab.ordered.indices.contains(next) else { return }
        withAnimation(.easeOut(duration: 0.2)) { appState.selectedTab = AppTab.ordered[next] }
    }

}
#endif
