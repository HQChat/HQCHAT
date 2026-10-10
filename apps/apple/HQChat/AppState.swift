// Shared app state for macOS and iOS targets.

import SwiftUI
import SwiftData
import Foundation
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
    @Published var connectionError: String?
    /// Errors with no owning screen, presented once at the root.
    @Published var lastError: AppError?
    @Published var isConnecting = false
    @Published var connectionStatus: ConnectionStatus = .disconnected
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

    /// Opens Settings → Account: a tab switch on iOS, a sheet on macOS.
    func showAccountSettings() {
        #if os(iOS)
        selectedTab = .settings
        #else
        showingSettings = true
        #endif
        openAccountSettings = true
    }
    /// The profile already checked this session, so `initialize()` does not repeat it.
    private var unlockedProfileId: UUID?

    #if DEBUG
    /// The `UITEST_FRESH` wipe runs once per launch.
    private static var didResetForUITest = false
    #endif

    /// Serialises `initialize()`, which several views call.
    private var isInitializing = false

    /// The profile the live connection authenticated as, to detect a switch.
    private var connectedProfileId: UUID?

    enum ConnectionStatus: Equatable {
        case disconnected
        case connecting
        case connected
        case authenticated
        /// No network path at all (`.error` means the server was unreachable).
        case offline
        case error(String)
    }

    /// REST for control, MQTT for messages and presence.
    let session = ChatSession()
    /// The device's network path, shared by every consumer.
    let reachability = Reachability()
    private var modelContext: ModelContext?

    init() {
        reachability.onBecameOnline = { [weak self] in
            guard let self else { return }
            Log.app.info("[AppState] 📶 Network came back — waking reconnect")
            if case .offline = self.connectionStatus {
                self.connectionStatus = .connecting
            }
            self.wakeReconnect()
        }
        reachability.onInterfaceChanged = { [weak self] in
            guard let self else { return }
            Log.app.info("[AppState] 📶 Network interface changed — dropping the link")
            // A link bound to the old interface can look healthy for minutes: drop it
            // and cut any running backoff short.
            self.wakeReconnect()
            Task { await self.session.networkPathChanged() }
        }
    }


    // Reconnect state: jittered exponential backoff, capped at 30 s.
    @Published var isReconnecting = false
    fileprivate var reconnectAttempt = 0
    fileprivate var reconnectTask: Task<Void, Never>?
    /// Cuts the current backoff short (the network came back or moved).
    private var backoffWakeRequested = false
    private static let maxReconnectDelay: Double = 30.0
    /// How long to wait for the auth handshake after a socket reconnects.
    private static let authGrace: TimeInterval = 10.0
    @Published var userService: UserService?

    /// Going to the background: announces presence offline, so the push bridge
    /// wakes this device (iOS freezes the socket, so the broker would otherwise
    /// keep it online until keepalive lapses).
    func enterBackground() async {
        // Nothing is on screen now, so every arrival is announced.
        NotificationService.shared.isForeground = false
        guard isAuthenticated else { return }
        #if os(iOS)
        // Hold a background assertion until the presence frame reaches the socket.
        let task = UIApplication.shared.beginBackgroundTask(withName: "hq.presence")
        let announced = await session.setPresence(online: false)
        if !announced {
            // The socket was gone; the broker's Last-Will will mark us offline.
            Log.app.info("[AppState] could not announce offline before suspending — relying on the Last-Will")
        }
        if task != .invalid { UIApplication.shared.endBackgroundTask(task) }
        #else
        await session.setPresence(online: false)
        #endif
    }

    /// Back in front: re-announces presence and re-reads the graph. Messages
    /// received meanwhile are replayed by the persistent MQTT session.
    func enterForeground() async {
        NotificationService.shared.isForeground = true
        guard isAuthenticated else { return }
        guard session.isConnected else {
            // The link did not survive the background: reconnect.
            Log.app.info("[AppState] link is gone on foreground — reconnecting")
            isAuthenticated = false
            connectionStatus = .disconnected
            await disconnectSession()
            return
        }
        await session.setPresence(online: true)
        await session.refreshDirectory()
    }

    /// Drops held keys; called on background.
    func clearCachedKey() {
        profileManager?.clearCachedKey()
    }

    /// Loads profiles and, with one active, wires the session and connects.
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
            if userService == nil { userService = UserService(api: session.api) }
            isAuthenticated = true
            connectionStatus = .authenticated
            return
        }

        guard let profile = profileManager?.currentProfile else {
            hasActiveProfile = false
            return
        }
        if unlockedProfileId != profile.id {
            // Diagnostics only: sign-in is what proves key access.
            profileManager?.hasStoredKey()
            unlockedProfileId = profile.id
        }
        hasActiveProfile = true
        if userService == nil {
            userService = UserService(api: session.api)
        }

        // Recreated on every call, so a profile switch cannot leave the router
        // writing into the previous profile's rows.
        session.configure(modelContext: context, profileManager: profileManager)
        wireSessionCallbacks()

        // A different active profile needs a fresh connection and sign-in.
        if let connected = connectedProfileId, connected != profile.id {
            Log.app.info("[AppState] 🔄 Active profile changed — resetting connection")
            await resetConnectionState()
        }
        await connectToServer()
    }

    /// `UITEST_FRESH=1` (debug builds) starts UI tests from an empty store, once per launch.
    private func resetForUITestsIfAsked(_ context: ModelContext) {
        #if DEBUG
        guard ProcessInfo.processInfo.environment["UITEST_FRESH"] == "1", !Self.didResetForUITest else { return }
        Self.didResetForUITest = true
        _ = DataResetService.resetAllData(modelContext: context, profileManager: profileManager)
        #endif
    }

    private func wireSessionCallbacks() {
        // A dismissed unlock is a choice: return to profile selection, no retries.
        session.onUnlockFailed = { [weak self] in
            guard let self else { return }
            Log.app.info("[AppState] 🔒 Unlock dismissed — returning to profile selection")
            self.reconnectTask?.cancel()
            self.reconnectTask = nil
            self.isReconnecting = false
            self.unlockedProfileId = nil
            self.hasActiveProfile = false
            self.lastError = .validation("Unlock cancelled. Pick a profile to try again.")
            Task { await self.disconnectSession() }
        }
        session.onConnected = { [weak self] in self?.didConnect() }
        session.onDisconnect = { [weak self] in self?.handleDisconnect() }
    }

    /// Signed in: ends any reconnect cycle, asks for the message-read unlock,
    /// registers for push and claims the chosen username.
    private func didConnect() {
        isAuthenticated = true
        connectionStatus = .authenticated
        connectionError = nil
        reconnectAttempt = 0
        reconnectTask?.cancel()
        reconnectTask = nil
        // Asked now, while the biometric hardware is free; views also ask on
        // appear, but their tasks are cancelled on rebuild.
        Task { await MessageKeyGate.shared.unlock() }
        PushManager.shared.requestAndRegister()
        PushManager.shared.setSender { [weak self] token in
            try? await self?.userService?.registerPushToken(token)
        }
        Task { await claimDesiredUsername() }
    }

    /// - Parameter force: connect even if the state says connected (a stale socket).
    func connectToServer(force: Bool = false) async {
        if isConnecting && !force {
            return
        }

        if !force {
            switch connectionStatus {
            case .connected, .authenticated:
                return // Already connected
            default:
                break // Proceed with connection
            }
        }

        // No network path: say so rather than fail on transport.
        guard reachability.isOnline else {
            isConnecting = false
            connectionError = nil
            connectionStatus = .offline
            return
        }

        isConnecting = true
        connectionStatus = .connecting
        connectionError = nil

        do {
            try await performConnectAndAuth()
            isConnecting = false
        } catch {
            isConnecting = false
            if !reachability.isOnline {
                connectionError = nil
                connectionStatus = .offline
            } else {
                let errorMessage = Self.friendlyConnectError(error)
                connectionError = errorMessage
                connectionStatus = .error(errorMessage)
            }
            Log.app.error("[AppState] ❌ Failed to connect: \(String(describing: error))")
        }
    }

    /// Brings the link up via `session.reconnect()`, which re-uses the REST
    /// session and signs in again only when it must. A profile switch clears the
    /// session first (`resetConnectionState`), forcing a full sign-in.
    private func performConnectAndAuth() async throws {
        guard let currentProfile = profileManager?.currentProfile,
              currentProfile.publicKey != nil else {
            throw NSError(domain: "AppState", code: 1, userInfo: [NSLocalizedDescriptionKey: "No active profile"])
        }
        connectionStatus = .connected      // the UI labels this "Authenticating…"
        try await session.reconnect()
        connectedProfileId = currentProfile.id
    }

    /// Claims the username chosen at profile creation. A refusal drops the
    /// request and sets `usernameRejected` for the banner.
    func claimDesiredUsername() async {
        guard let profile = profileManager?.currentProfile,
              let desired = profile.desiredUsername, !desired.isEmpty else { return }
        do {
            try await userService?.setUsername(desired)
            profile.desiredUsername = nil
            usernameRejected = nil
            try? modelContext?.save()
        } catch {
            guard Self.isUsernameTaken(error) else { return }  // transient — retry next connect
            usernameRejected = desired
            profile.desiredUsername = nil                      // stop re-firing it
            try? modelContext?.save()
        }
    }

    /// Whether the server refused a username as taken (409 USERNAME_TAKEN).
    static func isUsernameTaken(_ error: Error) -> Bool {
        if case APIClient.APIError.badResponse(_, let body) = error {
            return body.contains("USERNAME_TAKEN")
        }
        return false
    }

    /// Tears down the connection so the next connect signs in as the new profile.
    private func resetConnectionState() async {
        reconnectTask?.cancel()
        reconnectTask = nil
        reconnectAttempt = 0
        isReconnecting = false
        await session.logout()
        isAuthenticated = false
        connectionError = nil
        connectionStatus = .disconnected
        connectedProfileId = nil
    }

    /// Called by `ChatSession` when the link drops unexpectedly.
    func handleDisconnect() {
        guard reconnectTask == nil else { return }
        isAuthenticated = false
        isReconnecting = true
        connectionStatus = reachability.isOnline ? .connecting : .offline
        scheduleReconnect()
    }

    /// Reconnects with full-jitter exponential backoff until sign-in succeeds,
    /// parked while the device is offline.
    private func scheduleReconnect() {
        reconnectTask?.cancel()
        reconnectTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                if !self.reachability.isOnline {
                    self.connectionStatus = .offline
                    self.reconnectAttempt = 0
                    await self.reachability.waitUntilOnline()
                    if Task.isCancelled { break }
                    self.connectionStatus = .connecting
                }

                let ceiling = min(pow(2.0, Double(self.reconnectAttempt)), Self.maxReconnectDelay)
                let delay = Double.random(in: 0...ceiling)
                Log.app.info("[AppState] 🔄 Reconnect attempt \(String(describing: self.reconnectAttempt + 1)) in \(String(describing: String(format: "%.1f", delay)))s")
                await self.backoff(seconds: delay)
                if Task.isCancelled { break }
                self.reconnectAttempt += 1

                do {
                    try await self.performConnectAndAuth()
                } catch {
                    Log.app.warning("[AppState] ⚠️ Reconnect attempt failed: \(String(describing: error))")
                    continue
                }

                // On success the auth callback cancels this task; this poll is the failure path.
                if await self.awaitAuthentication(timeout: Self.authGrace) {
                    self.isReconnecting = false
                    break
                }
                if Task.isCancelled { break }
            }
        }
    }

    /// The network came back or moved: retry now.
    private func wakeReconnect() {
        guard reconnectTask != nil else { return }
        reconnectAttempt = 0
        backoffWakeRequested = true
    }

    /// A backoff sleep `wakeReconnect` can cut short.
    private func backoff(seconds: Double) async {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline, !backoffWakeRequested, !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        backoffWakeRequested = false
    }

    /// Whether sign-in completes within `timeout`.
    private func awaitAuthentication(timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if Task.isCancelled { return false }
            if case .authenticated = connectionStatus { return true }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        if case .authenticated = connectionStatus { return true }
        return false
    }

    /// A readable sentence for a server error code, or the text itself.
    private static func serverErrorMessage(_ payload: String) -> String {
        switch payload {
        case "USER_NOT_FOUND":
            return "No account with that username."
        case "USERNAME_TAKEN":
            return "That username is already taken. Try another."
        case "NOT_FRIENDS":
            return "You're not connected with that person."
        case "INVALID_MESSAGE", "INVALID_PAYLOAD":
            return "The server rejected that request."
        case "RATE_LIMITED":
            return "Too many requests. Wait a moment and try again."
        default:
            return payload
        }
    }

    private static func friendlyConnectError(_ error: Error) -> String {
        // Match `URLError.Code`, not localized text.
        if let urlError = error as? URLError {
            switch urlError.code {
            case .notConnectedToInternet:
                return "No internet connection.\n\nCheck Wi-Fi or cellular and try again."
            case .networkConnectionLost:
                return "The connection was lost.\n\nRetrying automatically."
            case .timedOut:
                return "The server took too long to respond.\n\nIt may be overloaded or unreachable."
            case .cannotConnectToHost, .cannotFindHost:
                return "Cannot reach the server.\n\nPlease check the server address and try again."
            case .secureConnectionFailed, .serverCertificateUntrusted,
                 .serverCertificateHasBadDate, .serverCertificateNotYetValid,
                 .serverCertificateHasUnknownRoot:
                return "The server's security certificate was rejected.\n\nThe connection was refused to protect your messages."
            default:
                break
            }
        }

        let description = error.localizedDescription
        if description.contains("Socket is not connected") {
            return "Cannot connect to the server.\n\nPlease ensure the server is running and accessible."
        }
        return "Connection failed. The server may be offline or unreachable.\n\nError: \(description)"
    }
    
    /// Reconnects right away on returning to the foreground.
    func reconnectIfNeeded() async {
        guard hasActiveProfile else { return }
        // Ask the socket, not the flag: a socket can die while suspended.
        if isAuthenticated, session.isConnected { return }
        isAuthenticated = false
        // An attempt is already running (cold launch): do not start a second.
        guard !isConnecting else { return }
        guard reachability.isOnline else {
            connectionStatus = .offline
            return
        }
        // A running reconnect loop retries now.
        if reconnectTask != nil {
            reconnectAttempt = 0
            scheduleReconnect()
            return
        }
        await connectToServer(force: true)
    }

    func authenticate() async {
        if userService == nil {
            await initialize()
        } else {
            await connectToServer()
        }
    }
    
    func getSession() -> ChatSession {
        return session
    }

    func disconnectSession() async {
        await session.disconnect()
    }

    // MARK: - Account

    /// Deletes the active profile's account (App Store Guideline 5.1.1(v)):
    /// asks the server to purge it, then deletes that profile and its keys from
    /// this device and returns to profile selection. Other profiles are kept.
    /// The profile is deleted even if the server call fails.
    func deleteAccount() async throws {
        let profile = profileManager?.currentProfile
        if isAuthenticated {
            try? await userService?.deleteAccount()
        }
        await resetConnectionState()
        if let profile { try profileManager?.deleteProfile(profile) }
        profileManager?.loadProfiles()
        hasActiveProfile = false
    }
}
