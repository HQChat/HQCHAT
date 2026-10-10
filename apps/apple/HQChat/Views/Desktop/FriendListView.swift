#if os(macOS)
import SwiftUI
import SwiftData

/// The macOS shell: friends (or user search results) in a sidebar, the open conversation beside it.
struct FriendListView: View {
    @Environment(\.modelContext) private var modelContext
    @EnvironmentObject var appState: AppState
    @Query(sort: \Friend.username) private var allFriends: [Friend]

    @StateObject private var friendService: FriendService
    @StateObject private var userService: UserService
    @State private var newFriendUsername = ""
    @State private var showingAddFriend = false
    @State private var selectedFriend: Friend?
    @State private var errorMessage: String?
    @State private var searchText = ""
    @State private var friendToRemove: Friend?

    let session: ChatSession
    let profileManager: ProfileManager?

    init(session: ChatSession, userService: UserService, profileManager: ProfileManager? = nil) {
        self.session = session
        self.profileManager = profileManager
        _friendService = StateObject(wrappedValue: FriendService(session: session, profileManager: profileManager))
        _userService = StateObject(wrappedValue: userService)
    }

    /// The current profile's contacts.
    private var friends: [Friend] {
        guard let current = profileManager?.currentProfile else { return [] }
        return allFriends.filter { $0.profile?.id == current.id }
    }

    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                HQSearchField(placeholder: "search users…", text: $searchText)
                    .padding(.horizontal)
                    .padding(.bottom, 8)
                Group {
                    if searchText.isEmpty {
                        friendList
                    } else {
                        UserSearchResults(users: matchingUsers) { username in
                            newFriendUsername = username
                            showingAddFriend = true
                        }
                    }
                }
                .background(HQScreenBackground())
                .navigationTitle(searchText.isEmpty ? "Friends" : "Search Users")
                .toolbar { toolbar }
            }
        } detail: {
            if let friend = selectedFriend {
                ChatView(friend: friend, session: session, profileManager: profileManager)
            } else {
                VStack(spacing: 14) {
                    HQLogoMark(size: 64)
                    Text("select a conversation")
                        .font(HQFont.ui(15, weight: .semibold))
                        .foregroundColor(HQColor.textSecond)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .hqScreenBackground()
            }
        }
        .sheet(isPresented: $appState.showingSettings) {
            SettingsView(userService: userService, profileManager: profileManager)
                .environmentObject(appState)
        }
        .sheet(isPresented: $showingAddFriend) {
            AddFriendSheet(username: $newFriendUsername) { username in
                run {
                    try await friendService.sendFriendRequest(username: username)
                    newFriendUsername = ""
                    showingAddFriend = false
                }
            }
        }
        .alert("Error", isPresented: Binding(get: { errorMessage != nil },
                                             set: { if !$0 { errorMessage = nil } })) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
        }
        .alert("Remove Friend", isPresented: Binding(get: { friendToRemove != nil },
                                                     set: { if !$0 { friendToRemove = nil } })) {
            Button("Cancel", role: .cancel) { friendToRemove = nil }
            Button("Remove", role: .destructive) { if let friend = friendToRemove { remove(friend) } }
        } message: {
            Text("Are you sure you want to remove \(friendToRemove?.username ?? "") from your friends list?")
        }
        .onAppear {
            friendService.setModelContext(modelContext)
            if let profileManager { friendService.setProfileManager(profileManager) }
            Task { try? await friendService.requestFriendsList() }
            openDemoConversation()
        }
        // Lookup is by exact username, so it runs as the user types.
        .onChange(of: searchText) { _, query in
            Task { try? await userService.searchUsers(query: query) }
        }
    }

    private var matchingUsers: [UserListItem] {
        userService.userDirectory.filter {
            $0.username.localizedCaseInsensitiveContains(searchText) || $0.id.localizedCaseInsensitiveContains(searchText)
        }
    }

    @ViewBuilder
    private var friendList: some View {
        if friends.isEmpty {
            HQEmptyState(title: "no friends yet",
                         message: "add friends to start messaging securely",
                         actionTitle: "add friend",
                         action: { showingAddFriend = true })
        } else {
            List(friends, selection: $selectedFriend) { friend in
                NavigationLink(value: friend) {
                    FriendRow(friend: friend) {
                        run { try await friendService.acceptInvite(username: friend.username) }
                    }
                }
                .listRowBackground(Color.clear)
                .padding(.vertical, 4)
                .contextMenu {
                    if friend.inviteStatus == .accepted {
                        Button(role: .destructive) {
                            friendToRemove = friend
                        } label: {
                            Label("Remove Friend", systemImage: "person.crop.circle.badge.minus")
                        }
                    }
                }
            }
            .scrollContentBackground(.hidden)
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .primaryAction) {
            ConnectionStatusButton(appState: appState)
        }
        ToolbarItem(placement: .primaryAction) {
            Button {
                showingAddFriend = true
            } label: {
                Label("Add Friend", systemImage: "person.badge.plus")
            }
        }
        ToolbarItem(placement: .primaryAction) {
            Menu {
                Button {
                    appState.showingSettings = true
                } label: {
                    Label("Settings", systemImage: "gearshape")
                }
                Divider()
                Button {
                    Task { try? await friendService.requestFriendsList() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
        }
    }

    /// By row, not by handle: after an identity change two rows share a handle.
    private func remove(_ friend: Friend) {
        run {
            try await friendService.remove(friend: friend)
            if selectedFriend == friend { selectedFriend = nil }
        }
        friendToRemove = nil
    }

    /// Runs an action, surfacing its error.
    private func run(_ action: @escaping () async throws -> Void) {
        Task {
            do { try await action() } catch { errorMessage = error.localizedDescription }
        }
    }

    /// Demo mode opens Settings or the first conversation with messages, for screenshots.
    private func openDemoConversation() {
        guard PersistenceController.isDemo else { return }
        let env = ProcessInfo.processInfo.environment
        if env["DEMO_SETTINGS"] == "1" {
            appState.showingSettings = true
        } else if selectedFriend == nil, env["DEMO_NO_CHAT"] != "1" {
            selectedFriend = friends.first { !($0.messages?.isEmpty ?? true) } ?? friends.first
        }
    }
}

/// One contact: presence, invite or identity state, and accept for a received invite.
private struct FriendRow: View {
    let friend: Friend
    let onAccept: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            HQAvatar(name: friend.username, size: 44, glow: HQColor.purple, isOnline: friend.isOnline)
            VStack(alignment: .leading, spacing: 3) {
                Text(friend.username)
                    .font(HQFont.ui(16, weight: .semibold))
                    .foregroundColor(HQColor.textPrimary)
                status.font(HQFont.mono(11.5, weight: .medium))
            }
            Spacer()
            if friend.inviteStatus == .inviteReceived {
                Button(action: onAccept) {
                    Text("accept")
                        .font(HQFont.ui(13, weight: .semibold))
                        .foregroundColor(HQColor.onGreen)
                        .padding(.horizontal, 14).padding(.vertical, 7)
                        .background(LinearGradient(colors: [HQColor.greenBright, HQColor.greenDeep],
                                                   startPoint: .topLeading, endPoint: .bottomTrailing))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                }
                .buttonStyle(.plain)
            }
        }
    }

    @ViewBuilder
    private var status: some View {
        if friend.inviteStatus == .inviteSent {
            Text("invite sent").foregroundColor(HQColor.warning)
        } else if friend.inviteStatus == .inviteReceived {
            Text("invite received").foregroundColor(HQColor.purpleLight)
        } else if friend.isVanished {
            // The contact re-keyed: this row is history and nothing can be sent to it.
            HStack(spacing: 5) {
                Image(systemName: "exclamationmark.triangle.fill").font(.system(size: 9))
                Text("identity gone")
            }
            .foregroundColor(HQColor.warning)
        } else {
            HStack(spacing: 5) {
                Text(friend.isOnline ? "live" : "offline")
                    .foregroundColor(friend.isOnline ? HQColor.green : HQColor.textMuted)
                if friend.hasSession {
                    Text("· e2e").foregroundColor(HQColor.green)
                } else if !friend.hasPinnedKey {
                    Text("· awaiting key").foregroundColor(HQColor.textDim)
                }
            }
        }
    }
}

/// Directory matches for the sidebar search, each with an add button.
private struct UserSearchResults: View {
    let users: [UserListItem]
    let onAdd: (String) -> Void

    var body: some View {
        List(users, id: \.username) { user in
            HStack(spacing: 12) {
                HQAvatar(name: user.username, size: 40, glow: HQColor.purple)
                VStack(alignment: .leading, spacing: 3) {
                    Text("@\(user.username)")
                        .font(HQFont.ui(15, weight: .semibold))
                        .foregroundColor(HQColor.textPrimary)
                    Text("id \(user.id.prefix(5))…")
                        .font(HQFont.mono(11))
                        .foregroundColor(HQColor.textFaint)
                        .lineLimit(1)
                }
                Spacer()
                Button {
                    onAdd(user.username)
                } label: {
                    Image(systemName: "person.badge.plus")
                        .font(.system(size: 15))
                        .foregroundColor(HQColor.green)
                        .frame(width: 34, height: 34)
                        .background(HQColor.green.opacity(0.08))
                        .overlay(RoundedRectangle(cornerRadius: 3).stroke(HQColor.green.opacity(0.4), lineWidth: 1))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                }
                .buttonStyle(.plain)
            }
            .listRowBackground(Color.clear)
            .padding(.vertical, 4)
        }
        .scrollContentBackground(.hidden)
        .overlay {
            if users.isEmpty {
                HQEmptyState(title: "no users found",
                             message: "usernames must match exactly — check the spelling",
                             systemImage: "magnifyingglass")
            }
        }
    }
}

/// Sends an invite to a typed username.
private struct AddFriendSheet: View {
    @Binding var username: String
    let onAdd: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Username", text: $username)
                } header: {
                    Text("Friend's username")
                } footer: {
                    Text("They'll receive an invite to connect securely.")
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Add Friend")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        if !username.isEmpty { onAdd(username); dismiss() }
                    }
                    .disabled(username.isEmpty)
                }
            }
        }
        .sheetSizing()
    }
}
#endif
