// Shared app state for macOS and iOS targets.

import SwiftUI
import SwiftData
import Foundation
import HQChatCore
#if os(iOS)
import UIKit
#endif

/// The iPhone tab bar's tabs, declared outside the iOS-only view so AppState
/// can hold the selection on both platforms.
enum AppTab: Hashable {
    case chats, contacts, settings

    /// Tabs in bar order, so a swipe moves the way the bar reads.
    static let ordered: [AppTab] = [.chats, .contacts, .settings]

    /// Lets a UI test (or a demo run) open straight onto a given tab:
    /// `SIMCTL_CHILD_DEMO_TAB=contacts`.
    static var initialFromEnvironment: AppTab {
        switch ProcessInfo.processInfo.environment["DEMO_TAB"] {
        case "contacts": return .contacts
        case "settings": return .settings
        default: return .chats
        }
    }
}

@MainActor
class AppState: ObservableObject {
    @Published var isAuthenticated = false
    /// Errors with no owning screen, presented once at the root.
    @Published var lastError: AppError?
    @Published var connectionStatus: ConnectionStatus = .disconnected
    /// The link dropped after being up, and the core is bringing it back.
    @Published var isReconnecting = false
    @Published var profileManager: ProfileManager?
    @Published var hasActiveProfile = false
    @Published var showingProfileSwitcher = false  // iOS: drives the profile-switch sheet
    /// macOS: shows the Settings sheet (the root banners need to open it).
    @Published var showingSettings = false
    /// iOS: the selected tab (the root banners need to change it).
    @Published var selectedTab: AppTab = AppTab.initialFromEnvironment
    /// A username the server refused as taken; drives the banner offering another.
    @Published var usernameRejected: String?
    /// Set to push Settings → Account (the banner's "choose another" action).
    @Published var openAccountSettings = false
    /// The active profile's conversations and actions.
    @Published private(set) var chat: ChatStore?
    /// The one-time move of a 3.1.1 profile to the core.
    @Published private(set) var migration: MigrationState = .none

    enum MigrationState: Equatable {
        case none
        case running
        case failed(String)
    }

    enum ConnectionStatus: Equatable {
        case disconnected
        case connecting
        case connected
        case authenticated
        /// No network path at all (`.error` means the server was unreachable).
        case offline
        case error(String)
    }

    /// Opens Settings → Account: a tab switch on iOS, a sheet on macOS.
    func showAccountSettings() {
        #if os(iOS)
        selectedTab = .settings
        #else
        showingSettings = true
        #endif
        openAccountSettings = true
    }

    #if DEBUG
    /// The `UITEST_FRESH` wipe runs once per launch.
    private static var didResetForUITest = false
    #endif

    /// Serialises `initialize()`, which several views call.
    private var isInitializing = false
    private var wasConnected = false

    /// The device's network path, shared by every consumer.
    let reachability = Reachability()
    private var modelContext: ModelContext?

    init() {
        reachability.onBecameOnline = { [weak self] in
            guard let self else { return }
            Log.app.info("[AppState] 📶 Network came back")
            self.chat?.networkChanged()
            self.updateStatus()
        }
        reachability.onInterfaceChanged = { [weak self] in
            Log.app.info("[AppState] 📶 Network interface changed")
            // A link bound to the old interface can look healthy for minutes:
            // the core drops it and reconnects.
            self?.chat?.networkChanged()
        }
    }

    /// Going to the background: presence says offline (so the push bridge
    /// wakes this device), then the core forgets its keys.
    func enterBackground() async {
        // Nothing is on screen now, so every arrival is announced.
        NotificationService.shared.isForeground = false
        guard let chat else { return }
        #if os(iOS)
        // Hold a background assertion until the presence frame is written.
        let task = UIApplication.shared.beginBackgroundTask(withName: "hq.presence")
        await chat.enterBackground()
        if task != .invalid { UIApplication.shared.endBackgroundTask(task) }
        #else
        await chat.enterBackground()
        #endif
        chat.lock()
    }

    /// Back in front: online again, and the unlock that opens the history.
    func enterForeground() async {
        NotificationService.shared.isForeground = true
        guard let chat else { return }
        await chat.enterForeground()
        await chat.unlock()
    }

    /// Drops the unlock; called on background.
    func clearCachedKey() {
        profileManager?.clearCachedKey()
        chat?.lock()
    }

    /// Loads profiles and, with one active, opens its core and connects.
    /// Re-entrant calls return at once.
    func initialize() async {
        if isInitializing { return }
        isInitializing = true
        defer { isInitializing = false }

        let context = modelContext ?? PersistenceController.shared.container.mainContext
        modelContext = context
        if profileManager == nil {
            profileManager = ProfileManager(modelContext: context)
        }
        resetForUITestsIfAsked(context)

        // Reload, in case a profile was just created or switched.
        profileManager?.loadProfiles()
        profileManager?.loadActiveProfile()

        // Demo mode: show the seeded UI without biometrics or a server.
        if PersistenceController.isDemo {
            hasActiveProfile = true
            if chat == nil { chat = PersistenceController.demoStore() }
            isAuthenticated = true
            connectionStatus = .authenticated
            return
        }

        guard let profile = profileManager?.currentProfile else {
            hasActiveProfile = false
            return
        }
        hasActiveProfile = true
        if chat?.profileID != profile.id {
            await closeChat()
            do {
                chat = try open(profile)
            } catch {
                lastError = .unknown("This profile could not be opened: \(error.localizedDescription)")
                return
            }
        }
        await prepare(profile)
    }

    /// The core store for `profile`, wired to this state.
    private func open(_ profile: Profile) throws -> ChatStore {
        // Endpoints shown in the app follow the profile's home server.
        ServerConfig.activeHost = profile.serverHost
        let store = try ChatStore(profile: profile)
        store.onEffect = { [weak self] effect in
            if case .connection = effect { self?.updateStatus() }
        }
        store.onAccountDeleted = { [weak self] in
            Task { await self?.forgetDeletedAccount() }
        }
        return store
    }

    /// Makes sure the core holds the profile's identity (moving a 3.1.1
    /// profile once, or making a new identity), then connects.
    private func prepare(_ profile: Profile) async {
        guard let chat, let context = modelContext else { return }
        if !ChatStore.hasIdentity(profileID: profile.id) {
            if CoreMigration.isNeeded(for: profile) {
                migration = .running
                do {
                    _ = try await CoreMigration.run(profile: profile, into: chat, context: context)
                    migration = .none
                } catch {
                    migration = .failed(error.localizedDescription)
                    return
                }
            } else {
                do {
                    try await chat.createIdentity()
                    profile.clientID = chat.myID
                    try? context.save()
                } catch {
                    lastError = .keychain("This profile's key could not be created: \(error.localizedDescription)")
                    return
                }
            }
        }
        connect()
    }

    /// Retries the move after it failed (the screen's button).
    func retryMigration() async {
        guard let profile = profileManager?.currentProfile else { return }
        await prepare(profile)
    }

    /// Starts the core: it asks for the unlock, signs in and connects.
    private func connect() {
        guard let chat else { return }
        updateStatus()
        chat.start()
        PushManager.shared.requestAndRegister()
        PushManager.shared.setSender { [weak self] token in
            self?.chat?.registerPush(token)
        }
    }

    private func closeChat() async {
        await chat?.stop()
        chat = nil
        isAuthenticated = false
        wasConnected = false
        connectionStatus = .disconnected
    }

    /// The core's link state, in the status bar's words.
    private func updateStatus() {
        guard let chat else { return }
        let state = chat.connection
        let previous = connectionStatus
        switch state {
        case .connected:
            connectionStatus = .authenticated
            isAuthenticated = true
            isReconnecting = false
            if !wasConnected { Task { await claimDesiredUsername() } }
            wasConnected = true
        case .authenticating:
            connectionStatus = .connected
        case .connecting:
            connectionStatus = .connecting
            isReconnecting = wasConnected
        case .offline:
            connectionStatus = reachability.isOnline ? (wasConnected ? .connecting : .disconnected) : .offline
            isAuthenticated = false
            isReconnecting = wasConnected && reachability.isOnline
        }
        if previous != connectionStatus {
            Log.app.info("[AppState] link: \(String(describing: self.connectionStatus))")
        }
    }

    /// `UITEST_FRESH=1` (debug builds) starts UI tests from an empty store, once per launch.
    private func resetForUITestsIfAsked(_ context: ModelContext) {
        #if DEBUG
        guard ProcessInfo.processInfo.environment["UITEST_FRESH"] == "1", !Self.didResetForUITest else { return }
        Self.didResetForUITest = true
        _ = DataResetService.resetAllData(modelContext: context, profileManager: profileManager)
        #endif
    }

    /// A retry the user asked for (the status chip, the banner).
    func connectToServer(force: Bool = false) async {
        guard let chat else { return await initialize() }
        if case .failed = migration { return await retryMigration() }
        chat.reconnect()
    }

    /// Back in front: catch up, and reconnect if the link did not survive.
    func reconnectIfNeeded() async {
        guard hasActiveProfile, let chat else { return }
        chat.start()
    }

    /// Claims the username chosen at profile creation. A refusal drops the
    /// request and sets `usernameRejected` for the banner.
    func claimDesiredUsername() async {
        guard let profile = profileManager?.currentProfile,
              let desired = profile.desiredUsername, !desired.isEmpty, let chat else { return }
        do {
            try await chat.setUsername(desired)
            profile.desiredUsername = nil
            usernameRejected = nil
            try? modelContext?.save()
        } catch {
            guard ChatStore.isUsernameTaken(error) else { return }  // transient — retry next connect
            usernameRejected = desired
            profile.desiredUsername = nil                           // stop re-firing it
            try? modelContext?.save()
        }
    }

    func disconnectSession() async {
        await chat?.stop()
    }

    // MARK: - Account

    /// Deletes the active profile's account (App Store Guideline 5.1.1(v)):
    /// asks the server to purge it, then deletes that profile and its keys from
    /// this device and returns to profile selection. Other profiles are kept.
    /// The profile is deleted even if the server call fails.
    func deleteAccount() async throws {
        let profile = profileManager?.currentProfile
        if isAuthenticated {
            try? await chat?.deleteAccount()
        }
        await closeChat()
        if let profile { try profileManager?.deleteProfile(profile) }
        profileManager?.loadProfiles()
        hasActiveProfile = false
    }

    /// The server deleted the account (from this device or another): the
    /// core already wiped its store; the profile goes too.
    private func forgetDeletedAccount() async {
        guard let profile = profileManager?.currentProfile else { return }
        await closeChat()
        try? profileManager?.deleteProfile(profile)
        profileManager?.loadProfiles()
        hasActiveProfile = false
    }
}
