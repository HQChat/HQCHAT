// iOS entry point. Mirrors HQChatApp (macOS): launches the shared
// ContentView with the shared AppState and SwiftData container.

import SwiftUI
import SwiftData

@main
struct HQChatIOSApp: App {
    let persistenceController = PersistenceController.shared
    @StateObject private var appState = AppState()
    @UIApplicationDelegateAdaptor(PushAppDelegate.self) private var pushDelegate
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // Init Sentry crash reporting + memory-pressure early warning before any
        // app code runs, so a crash during startup is still captured.
        Observability.start()
    }

    var body: some Scene {
        WindowGroup {
            ZStack {
                ContentView()
                    .environmentObject(appState)
                    .modelContainer(persistenceController.container)
                    .task {
                        await appState.initialize()
                    }
            }
            // Nothing readable in the app switcher's snapshot or a screen capture.
            .hqPrivacyCover()
            .onChange(of: scenePhase) { _, phase in
                switch phase {
                case .background:
                    // Tell the server first, while there is a moment to send:
                    // from here on, messages are queued and pushed rather than
                    // relayed into a socket iOS is about to freeze. Then the
                    // core forgets its keys until the next unlock.
                    Task { await appState.enterBackground() }
                case .active:
                    // Online again, and the unlock that opens the history. The
                    // screens cannot ask: a view that stayed on screen does not
                    // re-run its `.task`.
                    Task { await appState.enterForeground() }
                default: break
                }
            }
        }
    }
}
