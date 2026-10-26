import SwiftUI

/// The notices above a conversation: an unverified key, a vanished identity, a block.
struct ChatBanners: View {
    let friend: Contact
    let isEmpty: Bool
    let onVerify: () -> Void

    var body: some View {
        // An empty conversation is the moment to compare safety numbers.
        if friend.hasSession, !friend.isKeyVerified, !friend.isVanished, isEmpty {
            HQBanner(
                kind: .warning,
                text: "verify \(friend.username)'s safety number to be sure it's them",
                actionTitle: "verify",
                action: onVerify
            )
        }
        if friend.isVanished {
            HQBanner(
                kind: .warning,
                text: "this identity is gone — @\(friend.username) now uses a different key",
                actionTitle: "what happened",
                action: onVerify
            )
        }
        if friend.isBlocked {
            HQBanner(kind: .warning, text: "you blocked @\(friend.username) — they can't reach you")
        }
    }
}

/// The conversation's top bar: back, the contact and its encryption status,
/// search, the report menu, and (macOS) the profile switcher.
struct ChatHeader: View {
    let friend: Contact
    let profileManager: ProfileManager?
    @Binding var isSearching: Bool
    let onVerify: () -> Void
    let onReport: () -> Void
    let onError: (AppError) -> Void

    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var appState: AppState
    @State private var showingProfileSelector = false

    var body: some View {
        HStack(spacing: 6) {
            HStack(spacing: 9) {
                #if os(iOS)
                // The navigation and tab bars are hidden; this is the way back.
                Button { dismiss() } label: {
                    Text("[<]")
                        .font(HQFont.mono(15, weight: .bold))
                        .foregroundColor(HQColor.green)
                        .hqTapTarget()
                }
                .buttonStyle(.plain)
                .accessibilityLabel("back to chats")
                #endif

                HQAvatar(name: friend.username, size: 38, glow: HQColor.purple, isOnline: friend.isOnline)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(friend.username)
                            .font(HQFont.ui(16, weight: .semibold))
                            .foregroundColor(HQColor.textPrimary)
                            .lineLimit(1)
                            .minimumScaleFactor(0.8)
                        if Deployment.isHelper(friend.peerID) {
                            HelperAIBadge()
                        }
                    }
                    SessionStatus(friend: friend, onVerify: onVerify)
                }
            }
            .layoutPriority(1)

            Spacer(minLength: 0)

            Button {
                withAnimation { isSearching.toggle() }
            } label: {
                Image(systemName: isSearching ? "xmark" : "magnifyingglass")
                    .font(.system(size: 15))
                    .foregroundColor(HQColor.textSecond)
                    .hqTapTarget()
            }
            .buttonStyle(.plain)
            .accessibilityLabel(isSearching ? "close search" : "search this conversation")

            // Reporting sits in a menu, away from the frequently used controls.
            Menu {
                Button(role: .destructive, action: onReport) {
                    Label("report @\(friend.username)", systemImage: "flag")
                }
            } label: {
                Image(systemName: "ellipsis")
                    .font(.system(size: 15))
                    .foregroundColor(HQColor.textSecond)
                    .hqTapTarget()
            }
            .buttonStyle(.plain)
            .accessibilityLabel("more actions for this conversation")

            #if os(macOS)
            if let profileManager, !profileManager.profiles.isEmpty {
                ProfileSwitchMenu(profileManager: profileManager,
                                  onManage: { showingProfileSelector = true },
                                  onError: onError)
            }
            #endif
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(HQColor.screen.opacity(0.5))
        .overlay(Rectangle().fill(HQColor.hairline).frame(height: 1), alignment: .bottom)
        .sheet(isPresented: $showingProfileSelector) {
            if let profileManager {
                ProfileSelectionView(profileManager: profileManager)
                    .environmentObject(appState)
            }
        }
    }
}

/// Online state and whether the contact's key is verified; tapping it opens verification.
private struct SessionStatus: View {
    let friend: Contact
    let onVerify: () -> Void

    private var presence: String { friend.isOnline ? "live" : "offline" }

    var body: some View {
        if friend.hasSession {
            Button(action: onVerify) {
                HStack(spacing: 4) {
                    Circle()
                        .fill(friend.isOnline ? HQColor.green : Color.gray)
                        .frame(width: 6, height: 6)
                        .shadow(color: (friend.isOnline ? HQColor.green : .clear).opacity(0.9), radius: 4)
                    // Never green when unverified: an unverified contact must not look reassuring.
                    Text("\(presence)·e2e·\(friend.isKeyVerified ? "ok" : "unverified")")
                        .font(HQFont.mono(11, weight: .medium))
                        .lineLimit(1)
                        .foregroundColor(friend.isKeyVerified ? HQColor.green : HQColor.warning)
                }
            }
            .buttonStyle(.plain)
            .accessibilityLabel("\(friend.username) is \(friend.isOnline ? "online" : "offline"), encrypted, "
                                + (friend.isKeyVerified ? "key verified" : "key not verified"))
            .accessibilityHint("opens key verification")
        } else {
            HStack(spacing: 5) {
                Circle().fill(Color.gray).frame(width: 6, height: 6)
                // Every message is encrypted; an unopened session opens on the first send.
                Text(friend.isReadyButUnopened ? "e2e·on first message" : "e2e·reconnecting")
                    .font(HQFont.mono(12, weight: .medium))
                    .lineLimit(1)
                    .foregroundColor(HQColor.textMuted)
            }
            .accessibilityLabel(friend.isReadyButUnopened
                ? "encryption starts with your first message to \(friend.username)"
                : "reconnecting the encrypted session with \(friend.username)")
        }
    }
}

#if os(macOS)
/// Switches the active profile from inside a conversation; ContentView reconnects on change.
private struct ProfileSwitchMenu: View {
    @ObservedObject var profileManager: ProfileManager
    let onManage: () -> Void
    let onError: (AppError) -> Void

    var body: some View {
        Menu {
            ForEach(profileManager.profiles) { profile in
                Button {
                    do {
                        try profileManager.switchToProfile(profile)
                    } catch {
                        onError(.from(error))
                    }
                } label: {
                    HStack {
                        Text("@\(profile.username)")
                        if profile.id == profileManager.currentProfile?.id {
                            Image(systemName: "checkmark")
                        }
                    }
                }
            }
            Divider()
            Button(action: onManage) {
                Label("Manage Profiles", systemImage: "person.2")
            }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "person.circle.fill").font(.title3)
                if let currentProfile = profileManager.currentProfile {
                    Text("@\(currentProfile.username)").font(.caption).fontWeight(.medium)
                }
                Image(systemName: "chevron.down").font(.caption2)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(Color.controlBackground.opacity(0.5))
            .clipShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
#endif

/// Filters the transcript as you type.
struct ChatSearchBar: View {
    @Binding var text: String

    var body: some View {
        HQSearchField(placeholder: "search this conversation…", text: $text)
            .padding(.horizontal)
            .padding(.vertical, 6)
            .transition(.move(edge: .top).combined(with: .opacity))
    }
}
