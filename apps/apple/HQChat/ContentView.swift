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
                            Task { await appState.initialize() }
                        }
                } else {
                    LoadingView(message: "Initializing profiles...")
                }
            } else if case .running = appState.migration {
                // Once, on the first launch after the update.
                LoadingView(message: "updating your data…")
            } else if case let .failed(reason) = appState.migration {
                MigrationFailedView(reason: reason)
            } else if let chat = appState.chat {
                // The app shows while signing in; banners carry the connection state.
                MainAppView(profileManager: appState.profileManager)
                    .environmentObject(chat)
            } else {
                LoadingView(message: "Initializing...")
                    .onAppear { Task { await appState.initialize() } }
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

/// The move to the core did not finish. Nothing was lost: the old data stays
/// until a move succeeds, and this offers to try again.
private struct MigrationFailedView: View {
    @EnvironmentObject var appState: AppState
    let reason: String

    var body: some View {
        VStack(spacing: 18) {
            HQLogoMark(size: 48)
            Text("your data could not be updated")
                .font(HQFont.ui(16, weight: .semibold))
                .foregroundColor(HQColor.textPrimary)
            Text(reason)
                .font(HQFont.ui(13))
                .foregroundColor(HQColor.textSecond)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Button("try again") { Task { await appState.retryMigration() } }
                .buttonStyle(HQPrimaryButtonStyle(height: 46))
                .frame(maxWidth: 240)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .hqScreenBackground()
    }
}

#Preview {
    ContentView()
        .environmentObject(AppState())
}
