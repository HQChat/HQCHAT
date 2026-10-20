import SwiftUI
import SwiftData

@main
struct HQChatApp: App {
    let persistenceController = PersistenceController.shared
    @StateObject private var appState = AppState()
    @NSApplicationDelegateAdaptor(PushAppDelegate.self) private var pushDelegate
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
                    // Presence offline, then the core forgets its keys.
                    Task { await appState.enterBackground() }
                case .active:
                    // Back online, and the one unlock that opens the history,
                    // asked from here because this handler outlives the views.
                    Task { await appState.enterForeground() }
                default: break
                }
            }
        }
    }
}
