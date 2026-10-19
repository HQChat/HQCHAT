#if os(iOS)
import SwiftUI

/// The Contacts tab: pending invites, established contacts, blocked and vanished
/// identities, and adding someone new.
struct ContactsView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var chat: ChatStore

    let profileManager: ProfileManager?

    @State private var path = NavigationPath()
    @State private var appError: AppError?
    @State private var friendToRemove: Contact?
    @State private var friendToBlock: Contact?

    private var scoped: [Contact] { chat.contacts.sorted { $0.username < $1.username } }

    private var incoming: [Contact] { scoped.filter { $0.inviteStatus == .inviteReceived } }
    private var outgoing: [Contact] { scoped.filter { $0.inviteStatus == .inviteSent } }
    private var accepted: [Contact] { scoped.filter { $0.inviteStatus == .accepted } }
    /// Read-only histories (a vanished identity, or one the user blocked) are
    /// listed apart from the people who can be written to.
    private var vanished: [Contact] { accepted.filter(\.isVanished) }
    private var blocked: [Contact] { scoped.filter(\.isBlocked) }
    private var reachable: [Contact] { accepted.filter { !$0.isVanished && !$0.isBlocked } }

    var body: some View {
        NavigationStack(path: $path) {
            VStack(spacing: 0) {
                HQScreenHeader(path: "contacts", appState: appState, profileManager: profileManager)
                if scoped.isEmpty {
                    HQEmptyState(title: "no contacts yet",
                                 message: "add someone by their username to start messaging securely")
                        .frame(maxHeight: .infinity)
                } else {
                    contactList
                }
                // At the bottom, within thumb reach, without pushing the list down.
                Button { path.append(Route.add) } label: {
                    HStack(spacing: 8) {
                        Text("[+]").font(HQFont.mono(14, weight: .heavy))
                        Text("add contact")
                    }
                }
                .buttonStyle(HQPrimaryButtonStyle(height: 46))
                .accessibilityLabel("add contact")
                .padding(.horizontal, 16)
                .padding(.top, 10)
                .padding(.bottom, 16)
            }
            .background(HQScreenBackground())
            // The prompt header names the screen.
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: Route.self) { _ in addContact }
            .hqError($appError)
            .alert("Remove contact", isPresented: isPresent($friendToRemove), presenting: friendToRemove) { friend in
                Button("Cancel", role: .cancel) {}
                Button("Remove", role: .destructive) { remove(friend) }
            } message: { friend in
                // A vanished identity has no friendship left to end; only the history goes.
                Text(friend.isVanished
                     ? "Delete this conversation with \(friend.username)? It's with an identity that no longer exists, so nothing is unfriended — the messages are just removed from this device."
                     : "Remove \(friend.username)? Your conversation and shared keys are deleted from this device.")
            }
            // An alert rather than a confirmationDialog, whose cancel action iOS 26
            // never delivers.
            .alert("Block contact", isPresented: isPresent($friendToBlock), presenting: friendToBlock) { friend in
                Button("Cancel", role: .cancel) {}
                Button("Block", role: .destructive) { block(friend) }
            } message: { friend in
                Text("Block \(friend.username)? They can no longer reach you and cannot add you again. Your conversation stays on this device, read-only, and you can unblock them later.")
            }
        }
    }

    private var contactList: some View {
        List {
            section("wants to connect", incoming) { friend in
                ContactRow(friend: friend, onAccept: { accept(friend) }, onCancel: { cancel(friend) })
            }
            section("invites you sent", outgoing) { friend in
                ContactRow(friend: friend, onCancel: { cancel(friend) })
            }
            section("contacts", reachable) { friend in
                ContactRow(friend: friend)
                    .swipeActions(edge: .trailing) {
                        Button(role: .destructive) {
                            friendToRemove = friend
                        } label: {
                            Label("Remove", systemImage: "person.crop.circle.badge.minus")
                        }
                        Button {
                            friendToBlock = friend
                        } label: {
                            Label("Block", systemImage: "hand.raised")
                        }
                        .tint(HQColor.warning)
                    }
            }
            // The block lives on the server, so it holds across devices and re-invites.
            section("blocked", blocked) { friend in
                ContactRow(friend: friend)
                    .swipeActions(edge: .trailing) {
                        Button {
                            run { try await chat.unblock(friend) }
                        } label: {
                            Label("Unblock", systemImage: "hand.raised.slash")
                        }
                        .tint(HQColor.green)
                    }
            }
            // The person re-keyed; their new identity is a separate contact above.
            section("identities that are gone", vanished) { friend in
                ContactRow(friend: friend)
                    .swipeActions(edge: .trailing) {
                        Button(role: .destructive) {
                            friendToRemove = friend
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
            }
        }
        .scrollContentBackground(.hidden)
        .refreshable { chat.refresh() }
    }

    @ViewBuilder
    private func section<Row: View>(_ title: String, _ friends: [Contact],
                                    @ViewBuilder row: @escaping (Contact) -> Row) -> some View {
        if !friends.isEmpty {
            Section(header: HQFieldLabel(text: title)) {
                ForEach(friends) { friend in
                    row(friend).listRowBackground(Color.clear)
                }
            }
        }
    }

    private var addContact: some View {
        AddContactView(pendingUsernames: Set(outgoing.map(\.username)),
                       // A vanished identity's handle belongs to whoever holds it now.
                       contactUsernames: Set(accepted.filter { !$0.isVanished }.map(\.username)),
                       incomingUsernames: Set(incoming.map(\.username)),
                       myUsername: profileManager?.currentProfile?.username)
    }

    /// The single navigation destination of this tab.
    private enum Route: Hashable { case add }

    // MARK: Actions

    private func accept(_ friend: Contact) {
        run { try await chat.accept(friend) }
    }

    private func cancel(_ friend: Contact) {
        run { try await chat.cancel(friend) }
    }

    /// By id, not by handle: after an identity change two rows share a handle.
    private func remove(_ friend: Contact) {
        run { try await chat.remove(friend) }
    }

    private func block(_ friend: Contact) {
        run { try await chat.block(friend) }
    }

    /// Runs a friend-graph action, surfacing its error.
    private func run(_ action: @escaping () async throws -> Void) {
        Task {
            do { try await action() } catch { appError = .from(error) }
        }
    }

    /// Presents while `item` is set; dismissal clears it.
    private func isPresent<T>(_ item: Binding<T?>) -> Binding<Bool> {
        Binding(get: { item.wrappedValue != nil }, set: { if !$0 { item.wrappedValue = nil } })
    }
}
#endif
