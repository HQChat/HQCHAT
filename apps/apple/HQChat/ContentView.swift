import SwiftUI
import SwiftData

/// The root: profile selection until a profile is active, then the app.
struct ContentView: View {
    @EnvironmentObject var appState: AppState
    /// `HQFont` scales through `UIFontMetrics`, which SwiftUI does not observe,
    /// so the root is keyed on the text size to rebuild when it changes.
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        Group {
            if !appState.hasActiveProfile {
                if let profileManager = appState.profileManager {
                    ProfileSelectionView(profileManager: profileManager)
                        .onChange(of: profileManager.currentProfile) { _, newProfile in
                            guard newProfile != nil else { return }
                            appState.hasActiveProfile = true
                            Task {
                                await appState.disconnectSession()
                                await appState.initialize()
                            }
                        }
                } else {
                    LoadingView(message: "Initializing profiles...")
                }
            } else if let userService = appState.userService {
                // The app shows while signing in; banners carry the connection state.
                MainAppView(session: appState.getSession(),
                            userService: userService,
                            profileManager: appState.profileManager)
            } else {
                LoadingView(message: "Initializing...")
                    .onAppear { Task { await appState.authenticate() } }
            }
        }
        // Errors that arrive with no owning screen.
        .hqError($appState.lastError)
        .id(dynamicTypeSize)
        .onAppear { Task { await appState.initialize() } }
        // Dark-first: system surfaces (lists, sheets, bars) match the themed screens.
        .preferredColorScheme(.dark)
        .tint(HQColor.green)
    }
}

#Preview {
    ContentView()
        .environmentObject(AppState())
        .modelContainer(for: [Friend.self, Message.self, PendingFrame.self])
}
