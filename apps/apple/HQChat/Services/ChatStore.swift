import CoreShell
import Foundation
import HQChatCore

/// The active profile's conversations, as the screens read them, and every
/// action they take. One per profile.
///
/// The Rust core (`Engine`) holds the protocol and the data: sign-in, the
/// friend graph, the broker session, the ratchet, the sealed history. Its
/// `CoreShell` carries out what the engine asks for (HTTP, the connection,
/// the timer, the unlock prompt). This class turns the engine's effects into
/// published state on the main actor, and the screens' taps into engine
/// commands. Nothing here touches key material.
@MainActor
final class ChatStore: ObservableObject {
    /// Friends, requests either way, and identities kept read-only.
    @Published private(set) var contacts: [Contact] = []
    /// The link to the broker.
    @Published private(set) var connection: ConnState = .offline
    /// The core holds its keys: history can be read and messages sent.
    @Published private(set) var isUnlocked = false
    /// The user declined the unlock; screens offer to ask again.
    @Published private(set) var unlockDeclined = false
    /// Messages of the conversations opened so far, oldest first, by peer.
    @Published private(set) var conversations: [String: [ChatMessage]] = [:]
    /// This profile's client id, once known.
    @Published private(set) var myID: String?

    let profileID: UUID
    private let engine: Engine?
    private let shell: CoreShell?
    private let http: (any HTTPPerformer)?
    private let baseURL: URL?
    /// Previews for the conversation list, by peer.
    private var lastMessages: [String: ChatMessage] = [:]
    /// Callers waiting for the server's answer to an action, oldest first.
    private var waiters: [Action: [Waiter]] = [:]

    private struct Waiter {
        let id = UUID()
        let continuation: CheckedContinuation<Void, Error>
    }
    /// Friends accepted on this device, greeted once their key is pinned.
    private var toGreet: Set<String> = []
    private var username: String?
    /// Requests already announced; nil until the server's first list.
    private var knownInvites: Set<String>?

    /// Called when the server deleted the account and the core wiped the profile.
    var onAccountDeleted: (() -> Void)?
    /// Called on every effect, after the state is updated (tests, the log).
    var onEffect: ((Effect) -> Void)?

    // MARK: - Opening

    /// The engine for `profile`, its store under Application Support, its
    /// vault on the Secure Enclave, and a shell on the pinned session.
    convenience init(profile: Profile) throws {
        try self.init(profileID: profile.id, username: profile.username,
                      server: Self.serverURL(for: profile),
                      vault: SecureEnclaveVault(profileID: profile.id))
    }

    /// The engine for `profileID` on `server`, with `vault`. `connections`
    /// replaces the platform's (the live check maps the stack's hosts).
    init(profileID: UUID, username: String?, server: URL, vault: KeyVault,
         connections: ((URLSession) -> any ConnectionFactory)? = nil) throws {
        self.profileID = profileID
        self.username = username
        let root = try Self.storeDirectory(for: profileID)
        #if os(iOS)
        let device = Device.ios
        #else
        let device = Device.macos
        #endif
        let engine = try Engine(
            config: Config(serverUrl: server.absoluteString, profileId: profileID.uuidString, device: device,
                           hqnPins: Deployment.hqnKeyPins),
            vault: vault,
            store: try FileStore(root: root)
        )
        let session = URLSession(configuration: .ephemeral, delegate: TLSPinningDelegate(), delegateQueue: nil)
        let http = URLSessionHTTP(session: session)
        self.engine = engine
        self.http = http
        self.baseURL = server
        let hooks = Hooks()
        shell = CoreShell(
            engine: engine,
            baseURL: server,
            http: http,
            connections: connections?(session) ?? PlatformConnections(webSocketSession: session),
            // The store unlocks the engine itself, so it knows it is unlocked;
            // the shell has nothing left to do.
            askToUnlock: { reason in
                await hooks.unlock(reason)
                return false
            },
            onEffect: { effect in Task { @MainActor in hooks.effect(effect) } }
        )
        hooks.effect = { [weak self] effect in self?.apply(effect) }
        hooks.unlock = { [weak self] reason in await self?.unlock(reason: reason) }
        myID = engine.myId()
    }

    /// A store with no engine, filled with sample data: DEBUG demo mode and
    /// previews, so the screens run without a server or an Enclave.
    init(demo contacts: [Contact], conversations: [String: [ChatMessage]], myID: String) {
        profileID = UUID()
        engine = nil
        shell = nil
        http = nil
        baseURL = nil
        self.contacts = contacts
        self.conversations = conversations
        self.myID = myID
        isUnlocked = true
        connection = .connected
    }

    /// Where every profile's core data lives; a test points it elsewhere.
    nonisolated(unsafe) static var rootOverride: URL?

    nonisolated static func coreRoot() throws -> URL {
        if let rootOverride { return rootOverride }
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                  appropriateFor: nil, create: true)
        return support.appendingPathComponent("core", isDirectory: true)
    }

    /// Where a profile's core data lives: one sealed file per item.
    nonisolated static func storeDirectory(for profileID: UUID) throws -> URL {
        try coreRoot().appendingPathComponent(profileID.uuidString, isDirectory: true)
    }

    /// Whether the core already holds this profile's identity.
    nonisolated static func hasIdentity(profileID: UUID) -> Bool {
        guard let root = try? storeDirectory(for: profileID) else { return false }
        return FileManager.default.fileExists(atPath: root.appendingPathComponent("state").path)
    }

    /// Deletes a profile's core data (the profile is being deleted).
    nonisolated static func deleteStore(profileID: UUID) {
        guard let root = try? storeDirectory(for: profileID) else { return }
        try? FileManager.default.removeItem(at: root)
    }

    /// The profile's home server, or the build's.
    static func serverURL(for profile: Profile) -> URL {
        if let host = profile.serverHost, let url = URL(string: "https://\(host)") { return url }
        return ServerConfig.apiBaseURL
    }

    // MARK: - Lifecycle

    /// Makes a new identity (a new profile). Needs no prompt: the state is
    /// sealed to the device key's public half.
    func createIdentity() async throws {
        guard let engine, let shell else { return }
        try await shell.perform { engine, _ in try engine.createIdentity() }
        isUnlocked = true
        myID = engine.myId()
    }

    /// Brings a 3.1.1 profile's data in (`Migration/`).
    func importState(_ data: ImportData) async throws {
        guard let engine, let shell else { return }
        try await shell.perform { engine, now in try engine.importState(data: data, now: now) }
        isUnlocked = true
        myID = engine.myId()
        reloadContacts()
    }

    /// Starts signing in and connecting; asks for the unlock first if needed.
    func start() {
        guard let shell else { return }
        let network = Self.network()
        Task { await shell.start(network: network) }
    }

    /// The network path changed: the engine reconnects as it sees fit.
    func networkChanged() {
        guard let shell else { return }
        let network = Self.network()
        Task { await shell.networkChanged(network) }
    }

    /// Restarts the link after an error the user wants to retry.
    func reconnect() {
        guard let shell else { return }
        let network = Self.network()
        Task {
            await shell.stop()
            await shell.start(network: network)
        }
    }

    /// Asks the user, then opens the core's keys. True when unlocked.
    @discardableResult
    func unlock(retry: Bool = false) async -> Bool {
        await unlock(reason: .read, retry: retry)
    }

    @discardableResult
    private func unlock(reason: UnlockReason, retry: Bool = false) async -> Bool {
        guard let engine, let shell else { return isUnlocked }
        if isUnlocked { return true }
        await MessageKeyGate.shared.unlock(reason: Self.prompt(reason), retry: retry || reason != .read)
        guard MessageKeyGate.shared.isUnlocked else {
            unlockDeclined = MessageKeyGate.shared.wasDeclined
            return false
        }
        do {
            try await shell.perform { engine, now in try engine.unlock(now: now) }
            isUnlocked = true
            unlockDeclined = false
            myID = engine.myId()
            reloadContacts()
            for peer in conversations.keys { loadConversation(peer) }
            return true
        } catch {
            Log.keys.error("[ChatStore] the core could not open its keys: \(String(describing: error))")
            return false
        }
    }

    /// Forgets the opened keys (background, profile switch). Frames that
    /// arrive meanwhile wait, sealed, for the next unlock.
    func lock() {
        guard let engine else { return }
        _ = engine.lock()
        isUnlocked = false
        conversations = conversations.mapValues { _ in [] }
        // The list's previews are message text too.
        lastMessages = [:]
        for i in contacts.indices { contacts[i].lastMessage = nil }
    }

    /// Going to the background: presence says offline, so the push bridge
    /// wakes this device for what arrives while iOS freezes the link.
    func enterBackground() async {
        guard let shell else { return }
        await shell.perform { engine, now in engine.setPresence(online: false, now: now) }
    }

    /// Back in front: online again, and a tick to catch up on the link.
    func enterForeground() async {
        guard let shell else { return }
        await shell.perform { engine, now in engine.setPresence(online: true, now: now) }
        await shell.perform { engine, now in engine.tick(now: now) }
    }

    /// Closes the link; the engine keeps its state.
    func stop() async {
        await shell?.stop()
    }

    // MARK: - Reads

    /// The conversation with `peer`, as loaded so far.
    func messages(with peer: String) -> [ChatMessage] {
        conversations[peer] ?? []
    }

    /// Loads (or reloads) the conversation with `peer` from the core.
    func loadConversation(_ peer: String, limit: UInt32 = 500) {
        guard let engine, !peer.isEmpty else { return }
        guard let page = try? engine.history(peer: peer, before: nil, limit: limit) else {
            if conversations[peer] == nil { conversations[peer] = [] }
            return
        }
        let messages = page.map(ChatMessage.init)
        conversations[peer] = messages
        if let last = messages.last { lastMessages[peer] = last }
    }

    /// The safety number with `peer`, to compare in person.
    func safetyNumber(with peer: String) -> String? {
        engine?.fingerprint(peer: peer)
    }

    /// Exact-username lookup → client id; usernames are not browsable.
    func lookup(username: String) async -> UserListItem? {
        guard let http, let baseURL,
              var components = URLComponents(url: baseURL.appendingPathComponent("users"),
                                             resolvingAgainstBaseURL: false) else { return nil }
        components.queryItems = [URLQueryItem(name: "username", value: username)]
        guard let url = components.url else { return nil }
        let (status, body) = await http.perform(method: .get, url: url, bearer: nil, body: Data())
        struct Answer: Decodable { let username: String; let id: String? }
        guard status == 200, let answer = try? JSONDecoder().decode(Answer.self, from: body),
              let id = answer.id else { return nil }
        return UserListItem(username: answer.username, id: id)
    }

    // MARK: - Actions

    /// Sends `text` to `peer`; the session opens first if needed. The message
    /// is stored before anything leaves, so a failure stays visible.
    func send(_ text: String, to peer: String) async throws {
        guard let shell else { return demoSend(text, to: peer) }
        if !isUnlocked, !(await unlock(retry: true)) {
            throw AppError.keychain("Unlock HQChat to send messages.")
        }
        do {
            try await shell.perform { engine, now in try engine.sendText(peer: peer, text: text, now: now) }
        } catch {
            throw Self.appError(error)
        }
    }

    /// Re-sends a failed message under its id.
    func retry(_ message: ChatMessage) {
        guard let shell else { return }
        Task { await shell.perform { engine, now in engine.retry(msgId: message.id, now: now) } }
    }

    /// Sends a friend request to a username.
    func invite(_ username: String) async throws {
        try await perform(.invite) { engine, _ in engine.invite(username: username) }
    }

    /// Accepts a request; the new friend is greeted once their key is pinned.
    func accept(_ contact: Contact) async throws {
        toGreet.insert(contact.peerID)
        try await perform(.accept) { engine, _ in engine.accept(peer: contact.peerID) }
    }

    /// Withdraws a request sent, or declines one received.
    func cancel(_ contact: Contact) async throws {
        let peer = contact.isPending ? contact.username : contact.peerID
        try await perform(.cancel) { engine, _ in engine.cancel(peer: peer) }
    }

    /// Ends a friendship, or forgets a vanished identity (which has no
    /// friendship left on the server).
    func remove(_ contact: Contact) async throws {
        if contact.isVanished {
            guard let shell else { return }
            do {
                try await shell.perform { engine, _ in try engine.forget(peer: contact.peerID) }
            } catch {
                throw Self.appError(error)
            }
            forgetConversation(contact.peerID)
            return
        }
        try await perform(.remove) { engine, _ in engine.remove(peer: contact.peerID) }
        forgetConversation(contact.peerID)
    }

    /// Blocks a friend: the conversation stays, read-only.
    func block(_ contact: Contact) async throws {
        try await perform(.block) { engine, _ in engine.block(peer: contact.peerID) }
    }

    /// Lifts a block; the two invite each other again to start over.
    func unblock(_ contact: Contact) async throws {
        try await perform(.unblock) { engine, _ in engine.unblock(peer: contact.peerID) }
    }

    /// Files a report (App Store Guideline 1.2), then blocks if asked.
    func report(_ contact: Contact, category: String, note: String?, messageID: String?,
                block: Bool) async throws {
        let input = ReportInput(peer: contact.peerID, reason: category,
                                msgId: messageID, note: note, block: block)
        try await perform(.report) { engine, _ in engine.report(report: input) }
        if block {
            // The block follows the report; its answer refreshes the list.
            try await wait(for: .block)
        }
    }

    /// Claims a username.
    func setUsername(_ name: String) async throws {
        try await perform(.setUsername) { engine, _ in engine.setUsername(username: name) }
        username = name
    }

    /// Deletes the account on the server; the core then wipes the profile.
    func deleteAccount() async throws {
        try await perform(.deleteAccount) { engine, _ in engine.deleteAccount() }
    }

    /// Registers this device's APNs token ("platform:hex").
    func registerPush(_ token: String) {
        guard let shell else { return }
        let hex = token.split(separator: ":", maxSplits: 1).last.map(String.init) ?? token
        #if DEBUG
        let sandbox = true
        #else
        let sandbox = false
        #endif
        Task { await shell.perform { engine, _ in engine.registerPush(token: .apns(token: hex, sandbox: sandbox)) } }
    }

    /// The conversation with `peer` was seen.
    func markRead(_ peer: String) {
        guard let shell, isUnlocked, !peer.isEmpty,
              contacts.contains(where: { $0.peerID == peer && $0.unread > 0 }) else { return }
        Task { try? await shell.perform { engine, _ in try engine.markRead(peer: peer) } }
    }

    /// Records whether the safety number with `peer` was compared.
    func setVerified(_ peer: String, _ verified: Bool) async throws {
        guard let shell else { return }
        do {
            try await shell.perform { engine, _ in try engine.setVerified(peer: peer, verified: verified) }
        } catch {
            throw Self.appError(error)
        }
    }

    /// Steps the ratchet with `peer` on the next message.
    func rotateKeys(_ peer: String) async throws {
        guard let shell else { return }
        if !isUnlocked, !(await unlock(retry: true)) { return }
        do {
            try await shell.perform { engine, _ in try engine.rotateKeys(peer: peer) }
        } catch {
            throw Self.appError(error)
        }
    }

    /// Re-reads friends and invites now (a resume re-syncs the directory).
    func refresh() {
        start()
    }

    // MARK: - Effects

    private func apply(_ effect: Effect) {
        switch effect {
        case let .messageAdded(message):
            let m = ChatMessage(message)
            if conversations[m.peer] != nil {
                conversations[m.peer, default: []].removeAll { $0.id == m.id }
                conversations[m.peer, default: []].append(m)
            }
            lastMessages[m.peer] = m
            reloadContacts()
        case let .messageStatus(msgId, status):
            let next = ChatMessage.DeliveryStatus(status)
            for (peer, list) in conversations {
                if let i = list.firstIndex(where: { $0.id == msgId }) {
                    conversations[peer]?[i].deliveryStatus = next
                }
            }
            for (peer, m) in lastMessages where m.id == msgId {
                lastMessages[peer]?.deliveryStatus = next
            }
        case .friendsChanged:
            reloadContacts()
            greetNewFriends()
        case .invitesChanged:
            reloadContacts()
            if knownInvites == nil {
                knownInvites = Set(contacts.filter { $0.inviteStatus == .inviteReceived }.map(\.peerID))
            }
        case let .presenceChanged(peer, online):
            if let i = contacts.firstIndex(where: { $0.peerID == peer }) {
                contacts[i].isOnline = online
            }
        case let .connection(state):
            connection = state
            // Signed in and synced: from here on a new request is announced.
            if state == .connected, knownInvites == nil {
                knownInvites = Set(contacts.filter { $0.inviteStatus == .inviteReceived }.map(\.peerID))
            }
        case let .notify(peer):
            // No peer: a first contact that arrived while locked, whose sender
            // is not proven yet, so the notification names no one.
            guard let peer else {
                NotificationService.shared.notifyFirstContact()
                break
            }
            let name = contacts.first { $0.peerID == peer }?.username ?? String(peer.prefix(8))
            NotificationService.shared.notifyMessage(from: name)
        case let .actionDone(action):
            resume(action, with: .success(()))
        case let .actionFailed(action, status, code):
            resume(action, with: .failure(Self.appError(action: action, status: status, code: code)))
        case .accountDeleted:
            onAccountDeleted?()
        case let .dropped(reason):
            ProtocolLog.record(.dropped(stage: "core", peerID: nil, reason: reason))
        case let .storageFailed(reason):
            Log.storage.error("[ChatStore] \(reason)")
        case .tierChanged, .http, .`open`, .write, .close, .timer, .needUnlock:
            break
        }
        onEffect?(effect)
    }

    /// Rebuilds the contact list from the core.
    private func reloadContacts() {
        guard let engine else { return }
        let friends = engine.friends().map { f -> Contact in
            if lastMessages[f.id] == nil, isUnlocked,
               let last = try? engine.history(peer: f.id, before: nil, limit: 1).first {
                lastMessages[f.id] = ChatMessage(last)
            }
            return Contact(f, lastMessage: lastMessages[f.id])
        }
        let known = Set(friends.map(\.peerID))
        let received = engine.invites().map(Contact.init).filter { !known.contains($0.peerID) }
        let sent = engine.sentInvites().map(Contact.init)
        // A request that arrives while the app runs is announced; the ones
        // already there at launch are not.
        if let known = knownInvites {
            for c in received where !known.contains(c.peerID) {
                NotificationService.shared.notifyInvite(from: c.username)
            }
            knownInvites = Set(received.map(\.peerID))
        }
        contacts = friends + received + sent
        let unread = friends.reduce(0) { $0 + $1.unread }
        NotificationService.shared.setCounts(unreadMessages: unread, pendingInvites: received.count)
    }

    /// Says hello, once, to a friend accepted on this device, so the
    /// conversation does not start empty and inert: the first message carries
    /// the handshake, which opens the session both ways. Not a tamper check.
    private func greetNewFriends() {
        for peer in toGreet {
            guard let c = contacts.first(where: { $0.peerID == peer && $0.inviteStatus == .accepted }),
                  c.hasPinnedKey, !c.isReadOnly else { continue }
            toGreet.remove(peer)
            guard c.lastMessage == nil, isUnlocked else { continue }
            let me = username ?? "someone"
            Task { try? await send("hello @\(c.username), i'm @\(me).", to: peer) }
        }
    }

    private func forgetConversation(_ peer: String) {
        conversations[peer] = nil
        lastMessages[peer] = nil
    }

    // MARK: - Waiting for the server

    /// Runs `command` and waits for the server's answer to `action`.
    private func perform(_ action: Action, _ command: @escaping (Engine, Int64) -> [Effect]) async throws {
        guard let shell else { return }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            enqueue(action, continuation)
            Task { await shell.perform(command) }
        }
    }

    /// Waits for the server's answer to an action already under way.
    private func wait(for action: Action) async throws {
        guard shell != nil else { return }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            enqueue(action, continuation)
        }
    }

    /// Queues a waiter. An answer that never comes (the link is down and
    /// stays down) fails it after 30 s rather than leaving a screen waiting.
    private func enqueue(_ action: Action, _ continuation: CheckedContinuation<Void, Error>) {
        let waiter = Waiter(continuation: continuation)
        waiters[action, default: []].append(waiter)
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 30_000_000_000)
            guard let self, let i = self.waiters[action]?.firstIndex(where: { $0.id == waiter.id }) else { return }
            self.waiters[action]?.remove(at: i).continuation.resume(throwing: AppError.network(.timedOut))
        }
    }

    /// Answers the oldest waiter for `action`.
    private func resume(_ action: Action, with result: Result<Void, Error>) {
        guard let waiter = waiters[action]?.first else { return }
        waiters[action]?.removeFirst()
        waiter.continuation.resume(with: result)
    }

    // MARK: - Platform

    private static func network() -> NetworkInfo {
        NetworkInfo(key: Reachability.currentNetworkKey, expensive: false)
    }

    /// What the prompt says the unlock is for.
    private static func prompt(_ reason: UnlockReason) -> String {
        switch reason {
        case .signIn: return "Sign in to HQChat"
        case .send: return "Send your message"
        case .read: return "Read your messages"
        }
    }

    // MARK: - Errors

    /// A server refusal or an unreachable server, in the app's words.
    nonisolated static func appError(action: Action, status: UInt16, code: String) -> AppError {
        if status == 0 && code.isEmpty { return .network(.cannotConnectToHost) }
        let message: String
        switch code {
        case "USER_NOT_FOUND", "NOT_FOUND": message = "No account with that username."
        case "USERNAME_TAKEN": message = "That username is already taken. Try another."
        case "ALREADY_FRIENDS": message = "You're already connected."
        case "SELF_INVITE": message = "You can't invite yourself."
        case "FRIEND_LIMIT": message = "The contact limit has been reached."
        case "NOT_FRIENDS", "NOT_A_MEMBER", "NO_CONVERSATION": message = "You're not connected with that person."
        case "RATE_LIMITED": message = "Too many requests. Wait a moment and try again."
        case "LOCKED": message = "Unlock HQChat to do that."
        case "NOT_REPORTABLE": message = "Only a message they sent can be reported."
        case "": message = "The server refused that (\(status))."
        default: message = code
        }
        return .server(code: code.isEmpty ? nil : code, message: message)
    }

    /// The core's own refusals.
    nonisolated static func appError(_ error: Error) -> AppError {
        switch error {
        case CoreError.NotAFriend: return .validation("Nothing can be sent to this contact.")
        case CoreError.NoPrekeys: return .crypto("They haven't finished setting up yet. Try again in a moment.")
        case CoreError.Locked: return .keychain("Unlock HQChat to do that.")
        default: return .from(error)
        }
    }

    /// Whether the server refused a username as taken.
    nonisolated static func isUsernameTaken(_ error: Error) -> Bool {
        if case let AppError.server(code, _) = error { return code == "USERNAME_TAKEN" }
        return false
    }

    // MARK: - Demo

    private func demoSend(_ text: String, to peer: String) {
        let m = ChatMessage(id: UUID().uuidString, peer: peer, isOutgoing: true, content: text,
                            timestamp: Date(), deliveryStatus: .sent)
        conversations[peer, default: []].append(m)
        if let i = contacts.firstIndex(where: { $0.peerID == peer }) { contacts[i].lastMessage = m }
    }
}

/// The shell's callbacks, filled in once the store exists.
private final class Hooks: @unchecked Sendable {
    var effect: @MainActor (Effect) -> Void = { _ in }
    var unlock: @MainActor (UnlockReason) async -> Void = { _ in }
}
