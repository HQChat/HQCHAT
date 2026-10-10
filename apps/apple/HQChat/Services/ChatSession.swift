import Foundation
import CryptoKit
import SwiftData

fileprivate func dlog(_ message: @autoclosure () -> String) {
    let text = message()
    Log.network.debug("\(text)")
}

/// The client's connection to the server: REST (`AuthService`, `APIClient`)
/// for sign-in, the friend graph, usernames, push and account deletion, and
/// MQTT (`MQTTService`) for messages, handshakes, presence and graph nudges.
/// The broker fans out ciphertext and queues it for offline clients; the
/// server is not in the message path.
@MainActor
final class ChatSession: ObservableObject {

    /// Authentication + MQTT link state, in the order they happen.
    enum State: Equatable {
        case idle
        case authenticating     // REST handshake (this is what needs the key)
        case connecting         // handshake done, MQTT dialling
        case connected          // CONNACK; messages flow
    }

    @Published private(set) var state: State = .idle

    let auth = AuthService()
    let api: APIClient
    private let mqtt: MQTTService
    private let backend = MQTTWireClient()

    private var modelContext: ModelContext?
    private var profileManager: ProfileManager?
    private var router: ConversationRouter?
    private var directory: DirectorySync?
    /// Our own published prekeys — what lets peers open a session with us while
    /// this device is offline.
    private var prekeys: PrekeyService?
    /// The KEM the ratchet rides on. A stored property rather than a call to
    /// `HQCKem()` at each use, so a test can substitute a stub.
    private let kem: RatchetKem = HQCKem()

    /// Raised when the link drops unexpectedly; AppState owns the backoff loop.
    var onDisconnect: (() -> Void)?
    /// Raised once per successful login+connect.
    var onConnected: (() -> Void)?
    /// The private key could not be read — a dismissed or failed unlock.
    var onUnlockFailed: (() -> Void)?

    init() {
        let auth = self.auth
        self.api = APIClient(auth: auth)
        self.mqtt = MQTTService(backend: backend, auth: auth)
    }

    // MARK: - Wiring

    func configure(modelContext: ModelContext, profileManager: ProfileManager?) {
        self.modelContext = modelContext
        self.profileManager = profileManager
        let prekeys = PrekeyService(api: api) { [weak profileManager] in
            profileManager?.currentProfile?.id
        }
        self.prekeys = prekeys
        let router = ConversationRouter(
            modelContext: modelContext,
            profileManager: profileManager,
            prekeys: prekeys,
            publish: { [weak self] friend, envelope in self?.publish(envelope, to: friend) },
            publishHandshake: { [weak self] bytes, friend in
                self?.publishHandshake(bytes, to: friend)
            },
            resendUnconfirmed: { [weak self] friend in await self?.resendUnconfirmed(to: friend) },
            sendReceipt: { [weak self] msgId, friend in await self?.sendReceipt(for: msgId, to: friend) },
            resyncDirectory: { [weak self] in _ = await self?.refreshDirectory() }
        )
        self.router = router
        self.directory = DirectorySync(api: api, modelContext: modelContext,
                                       profileManager: profileManager)

        Task { await self.installHandlers() }
    }

    /// Routes the transport's inbound traffic: frames, handshakes, graph nudges,
    /// presence and link state.
    private func installHandlers() async {
        await mqtt.setMessageHandler { [weak self] topic, payload in
            guard let self else { return }
            // The AAD is the frame's header bytes as they arrived.
            let result = ConversationFrame.decodeReporting(payload)
            guard let (frame, aad) = result.result else {
                ProtocolLog.record(.dropped(stage: "envelope-decode", peerID: nil,
                                            reason: result.reason))
                return
            }
            // The router checks this kind of frame may arrive on this topic.
            Task { @MainActor in await self.router?.handle(frame, aad: aad, topic: topic) }
        }
        await mqtt.setHandshakeHandler { [weak self] topic, payload in
            Task { @MainActor in await self?.router?.handleHandshake(payload, topic: topic) }
        }
        // Graph nudges are best effort; the directory poll is the floor.
        await mqtt.setGraphHandler { [weak self] in
            Task { @MainActor in _ = await self?.refreshDirectory() }
        }
        await mqtt.setPresenceHandler { [weak self] id, online in
            Task { @MainActor in self?.router?.setPresence(id: id, online: online) }
        }
        await mqtt.setConnectionHandler { [weak self] connected, error in
            Task { @MainActor in self?.linkChanged(connected: connected, error: error) }
        }
    }

    var isConnected: Bool { state == .connected }

    // MARK: - Login

    /// Full login: REST handshake (the one moment that needs the private key),
    /// then the friend graph, then MQTT. Throws on transport/auth failure so the
    /// caller can show it and schedule a retry.
    func connect() async throws {
        guard let profile = profileManager?.currentProfile,
              let publicKey = profile.publicKey else {
            throw AuthService.AuthError.notAuthenticated
        }

        // Endpoints follow the profile's home server (nil = the build default).
        ServerConfig.activeHost = profile.serverHost

        state = .authenticating
        // One unlock window covers the handshake AND the key-agreement burst that
        // follows it, so a login costs a single Face ID rather than one per friend.
        profileManager?.beginHandshakeUnlock()
        guard let secretKey = profileManager?.getSecretKey(reason: "sign in") else {
            profileManager?.endHandshakeUnlock()
            state = .idle
            onUnlockFailed?()
            throw AuthService.AuthError.notAuthenticated
        }

        _ = try await auth.login(publicKeyHex: publicKey.hexString, secretKey: secretKey)

        state = .connecting
        // The broker knows us by our CLIENT ID, not our key: it is the MQTT
        // client id, the username, and what `WHERE id = ${clientid}` matches in
        // the topic ACL.
        try await mqtt.connect(id: profile.peerID)
        // The graph is fetched in parallel with the MQTT dial; subscriptions are
        // applied when CONNACK lands (see linkChanged).
        await refreshDirectory()
    }

    /// Reconnects on the existing REST session, which registers a fresh MQTT
    /// signing key; only when that session is gone does it sign in again (and
    /// unlock the private key).
    func reconnect() async throws {
        guard let profile = profileManager?.currentProfile,
              let pk = profile.publicKey?.hexString else {
            throw AuthService.AuthError.notAuthenticated
        }
        // The REST session must belong to this profile's key; after a profile
        // switch it may still be the previous one's.
        guard let session = await auth.currentSession(), session.pk == pk else {
            try await connect()
            return
        }
        state = .connecting
        do {
            try await mqtt.connect(id: profile.peerID)
            await refreshDirectory()
        } catch {
            guard Self.needsFreshHandshake(error) else {
                // Transport trouble: retry without a handshake (which would prompt).
                dlog("[ChatSession] reconnect failed (\(error)) — transport, not auth; retrying without a handshake")
                state = .idle
                throw error
            }
            dlog("[ChatSession] session rejected (\(error)) — full re-login")
            try await connect()
        }
    }

    /// Whether a failed reconnect means our REST session is gone, as opposed to
    /// the network or the broker being unavailable.
    ///
    /// Only the first justifies spending a biometric prompt: a new handshake
    /// replaces a session the server will not accept, and does nothing whatever
    /// for a connection that never got there.
    private static func needsFreshHandshake(_ error: Error) -> Bool {
        switch error {
        case AuthService.AuthError.notAuthenticated:
            return true
        case AuthService.AuthError.badResponse(let code, _):
            // Only 401 (the bearer is dead) is fixed by a new handshake.
            return code == 401
        default:
            return false
        }
    }

    func disconnect() async {
        await mqtt.disconnect()
        state = .idle
        stopDirectoryPoll()
    }

    /// The network path moved (Wi-Fi to cellular, a new address). Drop the MQTT
    /// link rather than wait for the dead socket to notice; the disconnect it
    /// reports runs the ordinary reconnect.
    func networkPathChanged() async {
        await mqtt.abandonLink()
    }

    func logout() async {
        await disconnect()
        await auth.logout()
    }

    // MARK: - Directory

    /// Pull the friend graph, subscribe to every conversation, and start key
    /// agreement with anyone we do not yet share a channel with.
    @discardableResult
    func refreshDirectory() async -> [Friend] {
        guard let directory else { return [] }
        do {
            let friends = try await directory.sync()
            let unopened = friends.filter { !$0.hasSession }
            dlog("[ChatSession] 📇 directory: \(friends.count) friend(s), "
                 + "\(unopened.count) without a session"
                 + (unopened.isEmpty ? "" : " — \(unopened.map(\.username).joined(separator: ", "))"))
            // Accepted friendships only: pending invites have no topic ids yet.
            let subscribable = friends.compactMap { friend -> (id: String, topics: FriendTopics)? in
                guard friend.inviteStatus == .accepted, let topics = friend.topics else { return nil }
                return (id: friend.peerID, topics: topics)
            }
            await mqtt.subscribeFriends(subscribable)
            // Sessions open on the first send; keep our prekey bundle stocked so
            // peers can open one with us while we are offline.
            await prekeys?.ensurePublished()
            ProtocolLog.record(.directorySynced(
                friends: friends.count,
                withoutSession: unopened.count,
                withoutKey: friends.filter { !$0.hasPinnedKey }.count))
            return friends
        } catch {
            dlog("[ChatSession] directory sync failed: \(error)")
            return []
        }
    }

    // MARK: - Keeping the graph fresh

    private var directoryPoll: Task<Void, Never>?

    /// How often the friend graph is re-read while connected.
    private static let pollInterval: UInt64 = 60_000_000_000

    /// Re-reads the friend graph on a timer, in case a graph nudge was missed.
    private func startDirectoryPoll() {
        directoryPoll?.cancel()
        directoryPoll = Task { [weak self] in
            while !Task.isCancelled {
                let interval = Self.pollInterval
                // A cancelled sleep throws; returning (not `try?`) ends the loop.
                do { try await Task.sleep(nanoseconds: interval) } catch { return }
                guard let self, self.state == .connected else { return }
                await self.refreshDirectory()
            }
        }
    }

    private func stopDirectoryPoll() {
        directoryPoll?.cancel()
        directoryPoll = nil
    }

    /// Opens a session with `friend` from their published prekeys. False when
    /// they have published none, their key is not yet verified, or the claim
    /// fails; `lastSessionFailure` then says why.
    @discardableResult
    func startSession(with friend: Friend) async -> Bool {
        guard !friend.hasSession else { return true }
        guard !friend.isVanished else { return false }
        // The verified identity key must be in hand before claiming, which
        // consumes one of the peer's one-time prekeys.
        guard friend.hasPinnedKey else {
            dlog("[ChatSession] ❌ no verified identity key for \(friend.username) yet")
            ProtocolLog.record(.dropped(stage: "start-session", peerID: friend.peerID,
                                        reason: "no verified identity key pinned yet"))
            lastSessionFailure[friend.peerID] =
                "hasn't published a key we can verify yet — try again in a moment"
            return false
        }
        do {
            let claimed = try await api.claimPrekey(peer: friend.peerID)
            guard let mediumPk = Data(hexString: claimed.medium) else {
                dlog("[ChatSession] ❌ \(friend.username)'s medium-term prekey is not hex")
                return false
            }
            let oneTimePk = claimed.oneTime.flatMap { Data(hexString: $0.prekey) }
            if oneTimePk == nil {
                dlog("[ChatSession] ⚠️ \(friend.username) had no one-time prekey — "
                     + "this session's forward secrecy runs to their next rotation")
            }

            // The identity key is the pinned, id-verified one, never anything the
            // claim returned, so a substituted prekey cannot yield the root.
            let bundle = PrekeyBundle(
                identityPk: friend.publicKey,
                mediumPk: mediumPk,
                oneTimePk: oneTimePk,
                oneTimeId: oneTimePk == nil ? nil : claimed.oneTime?.id
            )
            let started = try RatchetSession.startAsInitiator(kem: kem, bundle: bundle)
            friend.ratchetSession = started.state
            dlog("[ChatSession] ✅ session opened with \(friend.username)")
            ProtocolLog.record(.sessionOpenedAsInitiator(peer: friend.peerID,
                                                         usedOneTime: oneTimePk != nil))
            return true
        } catch {
            dlog("[ChatSession] ❌ could not open a session with \(friend.username): \(error)")
            lastSessionFailure[friend.peerID] = Self.describe(error)
            return false
        }
    }

    /// Why the last attempt to open a session with a peer failed, if it did.
    private var lastSessionFailure: [String: String] = [:]

    /// Turn a claim failure into something worth showing a person.
    private static func describe(_ error: Error) -> String {
        if case APIClient.APIError.badResponse(let code, _) = error {
            switch code {
            case 404: return "hasn't set up encryption keys yet — they need to open the app once"
            case 403: return "isn't in your contacts on the server any more"
            case 409: return "can't be added — one of you has reached the contact limit"
            case 429: return "couldn't be reached — too many requests, try again shortly"
            default:  return "couldn't be reached (server said \(code))"
            }
        }
        return "couldn't be reached"
    }

    /// Seal `text` for `friend`, returning the frame to publish.
    ///
    /// Opens a session first if there is none, so a first message can be sent
    /// while the peer is offline.
    func sealMessage(_ text: String, to friend: Friend, msgId: String) async throws -> ConversationFrame {
        try await seal(text, kind: .message, to: friend, msgId: msgId)
    }

    /// Tells `friend` their message `msgId` arrived: a sealed, empty frame on the
    /// conversation, so the server sees one more message and nothing else.
    func sendReceipt(for msgId: String, to friend: Friend) async {
        // A receipt never opens a session, and is only sent inside an answered one.
        guard friend.hasSession, friend.ratchetSession?.pendingInit == nil else { return }
        do {
            publish(try await seal("", kind: .receipt, to: friend, msgId: msgId), to: friend)
        } catch {
            dlog("[ChatSession] receipt to \(friend.username) not sent: \(error)")
        }
    }

    private func seal(_ text: String, kind: ConversationFrame.Kind, to friend: Friend,
                      msgId: String) async throws -> ConversationFrame {
        if !friend.hasSession {
            await startSession(with: friend)
            guard friend.hasSession else {
                let why = lastSessionFailure[friend.peerID] ?? "couldn't be reached"
                throw AppError.crypto("\(friend.username) \(why).")
            }
        }
        guard var session = friend.ratchetSession else {
            throw AppError.crypto("Couldn't start a secure session with this contact yet.")
        }

        let sealed = try RatchetSession.seal(kem: kem, state: &session)
        // Present until the peer answers, so a failed or retried send still
        // carries the handshake (see RatchetSessionState.pendingInit).
        let initHeader = sealed.initHeader

        // The header is the AAD, so it is built before the payload is sealed.
        let isInit = initHeader != nil
        let fields = ConversationFrame(
            t: isInit ? .initiate : kind,
            sender: myID,
            to: friend.peerID,
            msgId: msgId,
            cid: sealed.header.cid,
            n: sealed.header.n,
            pn: sealed.header.pn,
            rk: initHeader?.rk ?? sealed.header.rk,
            // An init has no peer ratchet key to encapsulate against.
            kemCt: isInit ? nil : sealed.header.kemCt,
            ctId: initHeader?.ctId,
            ctMt: initHeader?.ctMt,
            ctOt: initHeader?.ctOt,
            otId: initHeader?.otId,
            // On `init` only; the peer verifies it against `sender`.
            senderPk: isInit ? Data(hexString: myPublicKeyHex) : nil
        )
        // Nil when the fields cannot make a well-formed frame (no profile, or
        // a contact whose id is not known yet).
        guard let aad = fields.header() else {
            throw AppError.crypto("\(friend.username) isn't ready to receive messages yet.")
        }
        let payload = try AESService.encryptRaw(plaintext: text,
                                                key: SymmetricKey(data: sealed.key),
                                                aad: aad)
        friend.ratchetSession = session
        return fields.withPayload(payload)
    }

    // MARK: - Messaging

    /// Our own client id — the `sender` on every frame we publish.
    var myID: String { profileManager?.currentProfile?.peerID ?? "" }

    /// Our own public key, hex. Needed on `init` frames alone (as `senderPk`),
    /// so a peer who has never fetched it can answer without a round trip.
    private var myPublicKeyHex: String { profileManager?.currentProfile?.publicKeyHex ?? "" }

    /// Publishes a frame to `friend`: an `init` to their inbox, which the broker
    /// queues while they are offline; anything else to the conversation topic.
    func publish(_ envelope: ConversationFrame, to friend: Friend) {
        let id = friend.peerID
        // Read on the main actor; the SwiftData model does not cross into the Task.
        let topics = friend.topics
        guard !id.isEmpty else { return }
        guard let data = envelope.encoded() else {
            dlog("[ChatSession] ❌ could not encode a \(envelope.t) frame for \(friend.username)")
            return
        }
        let isInit = envelope.t == .initiate
        Task {
            if isInit {
                await mqtt.sendToInbox(data, peerID: id)
                ProtocolLog.record(.initPublished(to: id))
            } else if let topics {
                await mqtt.send(data, on: topics)
            } else {
                dlog("[ChatSession] ❌ no topic ids for \(id.prefix(8))… yet — msg not sent (next sync names them)")
            }
        }
    }

    /// Publishes a handshake challenge or proof on the friendship's handshake
    /// topic, which only its two members hold.
    func publishHandshake(_ bytes: Data, to friend: Friend) {
        guard !friend.peerID.isEmpty, !myID.isEmpty, let topics = friend.topics else { return }
        Task { await mqtt.publishHandshake(bytes, on: topics) }
    }

    /// Seals, stores and publishes a message the app sends on the user's behalf.
    /// False (with nothing stored) when it could not be sent.
    @discardableResult
    func sendText(_ text: String, to friend: Friend) async -> Bool {
        guard let modelContext else { return false }
        let messageId = UUID().uuidString
        do {
            let envelope = try await sealMessage(text, to: friend, msgId: messageId)
            let message = Message(content: text, isOutgoing: true, friend: friend,
                                  messageId: messageId, deliveryStatus: .sending)
            modelContext.insert(message)
            publish(envelope, to: friend)
            message.advanceDelivery(to: friend.isOnline ? .sent : .queued)
            try? modelContext.save()
            return true
        } catch {
            dlog("[ChatSession] could not send on the user's behalf: \(error)")
            return false
        }
    }

    /// Re-sends every outgoing message to `friend` over the current session,
    /// after yielding a simultaneous session start. Message ids are kept, so a
    /// peer that already has one drops the duplicate.
    func resendUnconfirmed(to friend: Friend) async {
        let outgoing = (friend.messages ?? [])
            .filter { $0.isOutgoing }
            .sorted { $0.timestamp < $1.timestamp }
        guard !outgoing.isEmpty else { return }

        var sent = 0
        for message in outgoing {
            guard let id = message.messageId else { continue }
            do {
                let envelope = try await sealMessage(message.content, to: friend, msgId: id)
                publish(envelope, to: friend)
                sent += 1
            } catch {
                // Stop at the first failure so messages are not sent out of order.
                dlog("[ChatSession] resend to \(friend.username) stopped: \(error)")
                break
            }
        }
        ProtocolLog.record(.resent(peer: friend.peerID, count: sent))
        try? modelContext?.save()
    }

    /// Stop following an unfriended peer's topics.
    func unsubscribe(friend: Friend) async {
        await mqtt.unsubscribeFriend(friend.peerID)
    }

    /// Publishes presence explicitly (iOS freezes the socket rather than closing
    /// it, so the Last-Will would fire late). True once the frame reached the
    /// socket; false when it is only buffered or there is no session.
    @discardableResult
    func setPresence(online: Bool) async -> Bool {
        let written = await mqtt.publishPresence(online: online)
        ProtocolLog.record(.presenceAnnounced(online: online, written: written))
        return written
    }

    // MARK: - Link events

    private func linkChanged(connected: Bool, error: Error?) {
        if connected {
            state = .connected
            Task { _ = await refreshDirectory() }
            startDirectoryPoll()
            onConnected?()
        } else {
            let wasUp = state == .connected
            state = .idle
            stopDirectoryPoll()
            router?.clearAllPresence()
            if wasUp || error != nil { onDisconnect?() }
        }
    }

}
