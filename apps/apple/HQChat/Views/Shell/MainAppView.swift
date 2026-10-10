import SwiftUI

/// The signed-in app: connection and status banners above the platform shell
/// (a tab bar on iOS, a sidebar and split view on macOS).
struct MainAppView: View {
    @EnvironmentObject var appState: AppState
    let session: ChatSession
    let userService: UserService
    let profileManager: ProfileManager?
    @State private var showingProfileSelection = false
    
    @ViewBuilder
    private var adaptiveContent: some View {
        #if os(macOS)
        // Desktop: fixed-width profile sidebar beside the friend list.
        HStack(spacing: 0) {
            VStack {
                if let currentProfile = profileManager?.currentProfile {
                    VStack(spacing: 8) {
                        Image(systemName: "person.circle.fill")
                            .font(.system(size: 32))
                            .foregroundColor(.blue)

                        Text("@\(currentProfile.username)")
                            .font(.caption)
                            .fontWeight(.medium)
                            .lineLimit(1)
                            .truncationMode(.tail)

                        Button {
                            showingProfileSelection = true
                        } label: {
                            Text("Switch")
                                .font(.caption2)
                        }
                        .buttonStyle(.bordered)
                    }
                    .padding()
                    .frame(maxWidth: .infinity)
                    .background(Color.controlBackground)
                }

                Spacer()
            }
            .frame(width: 120)
            .background(Color.controlBackground)

            Divider()

            FriendListView(session: session, userService: userService, profileManager: profileManager)
        }
        #else
        RootTabView(
            session: session,
            userService: userService,
            profileManager: profileManager
        )
        #endif
    }

    var body: some View {
        VStack(spacing: 0) {
            // Above the platform fork, so both shells show them.
            ConnectionBanner(appState: appState)
            AppStatusBanners(appState: appState)
            adaptiveContent
        }
        #if os(iOS)
        // Full screen: the selector paints its own full-bleed backdrop.
        .fullScreenCover(isPresented: $showingProfileSelection) {
            profileSelectionSheet { showingProfileSelection = false }
        }
        .fullScreenCover(isPresented: $appState.showingProfileSwitcher) {
            profileSelectionSheet { appState.showingProfileSwitcher = false }
        }
        #else
        .sheet(isPresented: $showingProfileSelection) {
            profileSelectionSheet { showingProfileSelection = false }
        }
        .sheet(isPresented: $appState.showingProfileSwitcher) {
            profileSelectionSheet { appState.showingProfileSwitcher = false }
        }
        #endif
    }

    @ViewBuilder
    private func profileSelectionSheet(onSwitched: @escaping () -> Void) -> some View {
        if let profileManager = profileManager {
            ProfileSelectionView(profileManager: profileManager, onClose: onSwitched)
                .onChange(of: profileManager.currentProfile) { _, newProfile in
                    if newProfile != nil { onSwitched() }
                }
        }
    }
}
