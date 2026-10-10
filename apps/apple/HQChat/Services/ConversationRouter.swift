import Foundation
import SwiftData
import CryptoKit

/// Debug-level logging; the unified log keeps debug messages out of persisted logs.
fileprivate func dlog(_ message: @autoclosure () -> String) {
    let text = message()
    Log.network.debug("\(text)")
}

/// Applies inbound frames to the local store: verifies an `init`'s sender with
/// a handshake challenge, opens sessions, decrypts and stores messages.
/// Friends are resolved by client id.
@MainActor
final class ConversationRouter {

    private let modelContext: ModelContext
    private let profileManager: ProfileManager?
    /// Publishes a frame (injected by ChatSession; the router knows no transport).
    private let publish: (Friend, ConversationFrame) -> Void
    /// Publishes a handshake challenge or proof.
    private let publishHandshake: (Data, Friend) -> Void
    /// Re-sends everything outgoing to a contact after yielding a simultaneous start.
    private let resendUnconfirmed: (Friend) async -> Void
    /// Acknowledges a stored message to its sender.
    private let sendReceipt: (String, Friend) async -> Void
    /// Re-reads the friend graph when a frame names someone unknown.
    private let resyncDirectory: () async -> Void
    /// Our own published prekeys — the secrets that open an inbound `init`.
    private let prekeys: PrekeyService?
    private let kem: RatchetKem

    init(modelContext: ModelContext,
         profileManager: ProfileManager?,
         prekeys: PrekeyService?,
         kem: RatchetKem = HQCKem(),
         publish: @escaping (Friend, ConversationFrame) -> Void,
         publishHandshake: @escaping (Data, Friend) -> Void = { _, _ in },
         resendUnconfirmed: @escaping (Friend) async -> Void = { _ in },
         sendReceipt: @escaping (String, Friend) async -> Void = { _, _ in },
         resyncDirectory: @escaping () async -> Void = {}) {
        self.modelContext = modelContext
        self.profileManager = profileManager
        self.prekeys = prekeys
        self.kem = kem
        self.publish = publish
        self.publishHandshake = publishHandshake
        self.resendUnconfirmed = resendUnconfirmed
        self.sendReceipt = sendReceipt
        self.resyncDirectory = resyncDirectory
    }

    private var currentProfile: Profile? { profileManager?.currentProfile }
    private var myID: String { currentProfile?.peerID ?? "" }

    /// The private key for an inbound frame, opening the key-burst window so a
    /// burst of `init`s costs one unlock; the window never extends itself.
    private func getSecretKey(reason: String) -> Data? {
        guard let profileManager else { return nil }
        profileManager.beginKeyBurstUnlock()
        return profileManager.getSecretKey(reason: reason)
    }

    /// The active profile's contact with this client id.
    func friend(withID id: String) -> Friend? {
        guard let profileId = currentProfile?.id, !id.isEmpty else { return nil }
        let descriptor = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.peerID == id && $0.profile?.id == profileId }
        )
        return try? modelContext.fetch(descriptor).first
    }

    /// Senders we have already resynced the directory for, so a frame we still
    /// cannot place does not re-poll on every retry.
    private var resyncedFor: Set<String> = []

    /// The contact a frame is from, re-reading the directory once for an unknown
    /// sender (or one without topic ids): an invitee's first message can arrive
    /// before the inviter has synced. Only friends may publish to our inbox, so an
    /// unknown sender is a contact we have not learned about yet.
    private func friendResolving(_ id: String) async -> Friend? {
        let known = friend(withID: id)
        if let known, known.topics != nil { return known }
        guard !id.isEmpty, !resyncedFor.contains(id) else { return known }
        resyncedFor.insert(id)
        dlog("[ConversationRouter] · frame from an unknown \(id.prefix(8))… — resyncing the directory")
        ProtocolLog.record(.directoryResyncedForUnknownSender(peer: id))
        await resyncDirectory()
        return friend(withID: id)
    }

    // MARK: - Proving an `init` came from the peer it names
    //
    // Proving an `init` came from the peer it names: an `init` is built from
    // public values only, so the responder challenges the initiator with an HQC
    // encapsulation to its identity key (Handshake.swift) before opening it.

    /// How long a challenge stands. The initiator repeats its handshake on every
    /// frame until answered, so an expired one is retried by their next send.
    private static let handshakeTTL: TimeInterval = 60

    private struct PendingChallenge {
        let nonce: Data
        let expected: Data
        /// The held `init` and the AAD it opens against.
        let heldInit: (frame: ConversationFrame, aad: Data)
        let expiresAt: Date
    }

    /// Challenges we have issued and are waiting on, keyed by the peer's id.
    private var pendingChallenges: [String: PendingChallenge] = [:]
    /// Peers that have proven possession of their identity key this launch.
    private var proven: Set<String> = []

    private func sweepChallenges(_ now: Date = Date()) {
        for (peer, c) in pendingChallenges where c.expiresAt <= now {
            pendingChallenges.removeValue(forKey: peer)
            dlog("[ConversationRouter] · handshake with \(peer.prefix(8))… timed out — init dropped")
        }
    }

    /// Challenges an `init`'s sender to prove possession of its identity key.
    /// The key comes from the frame, whose decoder already checked that it
    /// hashes to the sender's id.
    private func challengeInitiator(_ friend: Friend, _ envelope: ConversationFrame, aad: Data) {
        guard let senderPk = envelope.senderPk else { return }
        sweepChallenges()

        let nonce = Handshake.nonce()
        guard let enc = try? kem.encapsulate(senderPk),
              let expected = Handshake.proof(ss: enc.ss, nonce: nonce,
                                             challenger: myID, prover: friend.peerID),
              let frame = Handshake.encode(.init(kind: .challenge, from: myID, to: friend.peerID,
                                                 nonce: nonce, ct: enc.ct, proof: nil))
        else {
            dlog("[ConversationRouter] ❌ could not build a challenge for \(friend.username)")
            return
        }
        pendingChallenges[friend.peerID] = PendingChallenge(
            nonce: nonce, expected: expected, heldInit: (envelope, aad),
            expiresAt: Date().addingTimeInterval(Self.handshakeTTL)
        )
        publishHandshake(frame, friend)
        ProtocolLog.record(.handshakeChallenged(peer: friend.peerID))
        dlog("[ConversationRouter] 🔐 challenged \(friend.username) — holding their init")
    }

    /// Handles a challenge or proof on the friendship's handshake topic.
    func handleHandshake(_ raw: Data, topic: String) async {
        guard let frame = Handshake.decode(raw) else { return }
        guard !myID.isEmpty, frame.to == myID, frame.from != myID else { return }
        guard let friend = friend(withID: frame.from), !friend.isVanished else { return }
        // It must arrive on our friendship's handshake topic with that peer.
        guard let topics = friend.topics, topic == topics.handshake else { return }

        switch frame.kind {
        case .challenge:
            // Answer only challenges for a handshake we started.
            guard friend.ratchetSession?.pendingInit != nil, let ct = frame.ct else { return }
            guard let sk = getSecretKey(reason: "proving your identity to \(friend.username)"),
                  let ss = try? kem.decapsulate(sk: sk, ct: ct),
                  let proof = Handshake.proof(ss: ss, nonce: frame.nonce,
                                              challenger: frame.from, prover: myID),
                  let reply = Handshake.encode(.init(kind: .proof, from: myID, to: frame.from,
                                                     nonce: frame.nonce, ct: nil, proof: proof))
            else { return }
            publishHandshake(reply, friend)
            ProtocolLog.record(.handshakeProved(peer: frame.from))
            dlog("[ConversationRouter] 🔐 proved our identity to \(friend.username)")

        case .proof:
            sweepChallenges()
            guard let pending = pendingChallenges[frame.from],
                  let offered = frame.proof,
                  pending.nonce == frame.nonce else { return }
            guard Handshake.proofMatches(expected: pending.expected, offered: offered) else {
                // Someone sent an `init` naming this peer without holding its key.
                dlog("[ConversationRouter] ❌ \(friend.username) FAILED the handshake — init discarded")
                ProtocolLog.record(.handshakeFailed(peer: frame.from))
                pendingChallenges.removeValue(forKey: frame.from)
                return
            }
            pendingChallenges.removeValue(forKey: frame.from)
            proven.insert(frame.from)
            ProtocolLog.record(.handshakeProven(peer: frame.from))
            dlog("[ConversationRouter] ✅ \(friend.username) proved possession — opening their init")
            await handleInit(from: friend, pending.heldInit.frame, aad: pending.heldInit.aad)
        }
    }

    // MARK: - Inbound

    /// - Parameters:
    ///   - aad: the header bytes as they arrived.
    ///   - topic: the topic the frame arrived on, checked against its kind.
    func handle(_ envelope: ConversationFrame, aad: Data, topic: String) async {
        // Our own publishes come back to us.
        guard let myID = currentProfile?.peerID, !myID.isEmpty else { return }
        if envelope.sender == myID { return }

        // The frame must be addressed to us (bound in the AAD) and arrive where its
        // sender may put it: an `init` on our inbox, anything else on our
        // conversation topic with that sender. Checked before any directory resync.
        if envelope.to != myID {
            dlog("[ConversationRouter] ❌ frame addressed to \(envelope.to.prefix(8))… — not ours")
            ProtocolLog.record(.dropped(stage: "recipient", peerID: envelope.sender,
                                        reason: "the frame names a different recipient"))
            return
        }

        // The expected topic, from contacts we already hold.
        let isInit = envelope.t == .initiate
        let senderTopics = isInit ? nil : friend(withID: envelope.sender)?.topics
        let expected = MQTTTopics.expected(forInit: isInit, senderTopics: senderTopics, me: myID)
        guard let expected, topic == expected else {
            dlog("[ConversationRouter] ❌ \(kindName(envelope)) from "
                 + "\(envelope.sender.prefix(8))… arrived on \(MQTTTopics.describe(topic)) — dropped")
            ProtocolLog.record(.dropped(stage: "topic-binding", peerID: envelope.sender,
                                        reason: expected.map { "a \(kindName(envelope)) from this sender may only arrive on \(MQTTTopics.describe($0))" }
                                            ?? "no conversation topic is known for this sender"))
            return
        }

        guard let friend = await friendResolving(envelope.sender) else {
            dlog("[ConversationRouter] ❌ no contact for \(envelope.sender.prefix(16))…")
            ProtocolLog.record(.dropped(stage: "envelope", peerID: envelope.sender,
                                        reason: "no contact row for this sender, even after a directory resync"))
            return
        }
        // A vanished identity cannot send; anything under its id is not this contact.
        if friend.isVanished {
            dlog("[ConversationRouter] ❌ frame for a vanished identity (\(friend.username)) — dropped")
            ProtocolLog.record(.dropped(stage: "envelope", peerID: friend.peerID,
                                        reason: "vanished identity — the server no longer lists this id"))
            return
        }
        switch envelope.t {
        case .initiate:
            ProtocolLog.record(.initReceived(from: friend.peerID,
                                             hasSenderPk: envelope.senderPk != nil))
            // Hold an unproven sender's `init` and challenge them; proof lasts for this launch.
            if !proven.contains(friend.peerID) {
                challengeInitiator(friend, envelope, aad: aad)
                return
            }
            await handleInit(from: friend, envelope, aad: aad)
        case .message:
            await handleMsg(from: friend, envelope, aad: aad)
        case .receipt:
            handleReceipt(from: friend, envelope, aad: aad)
        }
    }

    /// Opens a session from an inbound `init`, whose payload is the first message.
    private func handleInit(from friend: Friend, _ envelope: ConversationFrame, aad: Data) async {
        dlog("[ConversationRouter] 🤝 init ← \(friend.username)")
        // An inbound `init` never replaces an established session (it would let a
        // replay wipe a conversation).
        var yielding = false
        if friend.hasSession {
            guard let decision = await resolveCollision(friend, envelope, aad: aad) else { return }
            yielding = decision
        }
        pinSenderKey(friend, envelope)
        guard var session = deriveResponderSession(friend, envelope) else { return }

        // Open the payload before consuming the one-time key.
        guard let text = Self.openFrame(kem: kem, session: &session, envelope, aad: aad) else {
            return dropInit(friend, "session derived but the payload did not decrypt")
        }
        friend.ratchetSession = session
        if let otId = envelope.otId { prekeys?.consumeOneTime(id: otId) }
        store(text, from: friend, msgId: envelope.msgId)
        await sendReceipt(envelope.msgId, friend)
        dlog("[ConversationRouter] ✅ session open with \(friend.username)")
        ProtocolLog.record(.sessionOpenedAsResponder(peer: friend.peerID, usedOneTime: envelope.otId != nil))
        // After the session is in place, so the resend does not start another.
        if yielding { await resendUnconfirmed(friend) }
    }

    /// An `init` from a contact we already have a session with. Established (we
    /// have heard from them): its payload is an ordinary message. Our own `init`
    /// unanswered: both sides started at once, and the lower id keeps its own.
    /// Returns nil when handled here, true when yielding to theirs (our session
    /// is dropped and what we sent is re-sent over theirs).
    private func resolveCollision(_ friend: Friend, _ envelope: ConversationFrame, aad: Data) async -> Bool? {
        guard let myID = currentProfile?.peerID, !myID.isEmpty else { return nil }
        switch InitCollision.resolve(hasSession: true,
                                     heardFromThem: friend.ratchetSession?.pendingInit == nil,
                                     myID: myID, peerID: friend.peerID) {
        case .open:
            return false
        case .ignoreReplay:
            // An initiator repeats the init header until answered; the payload is a message.
            dlog("[ConversationRouter] · init from \(friend.username) — session already open, opening its payload as a message")
            ProtocolLog.record(.initIgnoredSessionOpen(peer: friend.peerID))
            await handleMsg(from: friend, envelope, aad: aad)
            return nil
        case .keepOurs:
            dlog("[ConversationRouter] · simultaneous init from \(friend.username) — keeping ours (lower id)")
            ProtocolLog.record(.initGlareKept(peer: friend.peerID))
            return nil
        case .yieldToTheirs:
            dlog("[ConversationRouter] · simultaneous init from \(friend.username) — yielding to theirs")
            ProtocolLog.record(.initGlareYielded(peer: friend.peerID))
            friend.ratchetSession = nil
            return true
        }
    }

    /// Pins the initiator's key from the frame (`pin` re-checks it against the id).
    private func pinSenderKey(_ friend: Friend, _ envelope: ConversationFrame) {
        guard let senderPk = envelope.senderPk?.hexString, !friend.hasPinnedKey else { return }
        if friend.pin(publicKeyHex: senderPk) {
            dlog("[ConversationRouter] 🔑 pinned \(friend.username)'s key from their init")
            ProtocolLog.record(.keyPinned(peer: friend.peerID, source: .initFrame))
        } else {
            ProtocolLog.record(.keyRejected(peer: friend.peerID, reason: "senderPk does not hash to sender"))
        }
    }

    /// The responder's session for an `init`, or nil (logged) when it cannot be derived.
    private func deriveResponderSession(_ friend: Friend, _ envelope: ConversationFrame) -> RatchetSessionState? {
        guard let secretKey = getSecretKey(reason: "opening a session with \(friend.username)") else {
            dropInit(friend, "identity key unreadable (unlock dismissed?)")
            return nil
        }
        guard let prekeys, let secrets = prekeys.secrets(identitySk: secretKey) else {
            dropInit(friend, "this profile has published no prekeys")
            return nil
        }
        guard let header = Self.initHeader(from: envelope) else {
            dropInit(friend, "malformed init header")
            return nil
        }
        guard let session = RatchetSession.startAsResponder(kem: kem, secrets: secrets, header: header) else {
            // A consumed one-time key or a foreign ciphertext: ordinary, not alarming.
            dropInit(friend, "one-time secret already consumed, or not our ciphertext")
            return nil
        }
        return session
    }

    private func dropInit(_ friend: Friend, _ reason: String) {
        dlog("[ConversationRouter] ❌ init from \(friend.username) dropped — \(reason)")
        ProtocolLog.record(.dropped(stage: "init", peerID: friend.peerID, reason: reason))
    }

    /// Decrypts and stores a message. The header is AAD, so a tampered header
    /// yields no message rather than a wrong one.
    private func handleMsg(from friend: Friend, _ envelope: ConversationFrame, aad: Data) async {
        guard var session = friend.ratchetSession else {
            dlog("[ConversationRouter] ❌ no session with \(friend.username)")
            ProtocolLog.record(.messageUndecryptable(peer: friend.peerID,
                                                     reason: "no session — their init never arrived"))
            return
        }
        guard let text = Self.openFrame(kem: kem, session: &session, envelope, aad: aad) else {
            // A replay, a retired chain, a gap too large, or a failed tag: ordinary,
            // and `open` committed nothing, so there is nothing to write back.
            dlog("[ConversationRouter] · no key for \(friend.username) frame "
                 + "(cid \(envelope.cid.prefix(8))…, n \(envelope.n))")
            ProtocolLog.record(.messageUndecryptable(peer: friend.peerID,
                                                     reason: "no key for this position (replay, retired chain, too large a gap, or a payload that did not authenticate)"))
            return
        }

        friend.ratchetSession = session
        store(text, from: friend, msgId: envelope.msgId)
        ProtocolLog.record(.messageDecrypted(peer: friend.peerID))
        await sendReceipt(envelope.msgId, friend)
    }

    /// Marks our message `envelope.msgId` delivered once the receipt authenticates.
    private func handleReceipt(from friend: Friend, _ envelope: ConversationFrame, aad: Data) {
        guard var session = friend.ratchetSession,
              Self.openFrame(kem: kem, session: &session, envelope, aad: aad) != nil else {
            ProtocolLog.record(.messageUndecryptable(peer: friend.peerID,
                                                     reason: "a receipt that did not authenticate"))
            return
        }
        friend.ratchetSession = session
        let msgId = envelope.msgId
        if let message = (friend.messages ?? []).first(where: { $0.isOutgoing && $0.messageId == msgId }) {
            message.advanceDelivery(to: .delivered)
        }
        try? modelContext.save()
    }

    /// Stores a decrypted message and refreshes the badges, dropping a `msgId`
    /// already stored from this contact (a re-send seals the same message at a
    /// new ratchet position).
    private func store(_ text: String, from friend: Friend, msgId: String) {
        if !msgId.isEmpty, alreadyStored(msgId: msgId, from: friend) {
            dlog("[ConversationRouter] · duplicate \(msgId.prefix(8))… from \(friend.username) — not stored twice")
            return
        }
        let message = Message(content: text, isOutgoing: false, friend: friend,
                              messageId: msgId.isEmpty ? nil : msgId)
        modelContext.insert(message)
        try? modelContext.save()

        NotificationService.shared.notifyMessage(from: friend.username)
        NotificationService.shared.refreshCounts(modelContext: modelContext,
                                                profileID: currentProfile?.id)
    }

    /// Opens one frame: the ratchet proposes a key and the AEAD tag decides,
    /// which is the only authentication (a forged HQC ciphertext decapsulates
    /// without error). `session` is unchanged whenever this returns nil.
    private static func openFrame(kem: RatchetKem,
                                  session: inout RatchetSessionState,
                                  _ envelope: ConversationFrame,
                                  aad: Data) -> String? {
        var plaintext: String?
        let opened = RatchetSession.open(kem: kem, state: &session,
                                         header: Self.messageHeader(from: envelope)) { mk in
            guard let text = try? AESService.decryptRaw(ciphertext: envelope.payload,
                                                        key: SymmetricKey(data: mk), aad: aad) else {
                return false
            }
            plaintext = text
            return true
        }
        return opened == nil ? nil : plaintext
    }

    /// Whether this contact's `msgId` is already stored (ids are only unique per sender).
    private func alreadyStored(msgId: String, from friend: Friend) -> Bool {
        let peerID = friend.peerID
        guard !peerID.isEmpty else { return false }
        var descriptor = FetchDescriptor<Message>(
            predicate: #Predicate<Message> { $0.messageId == msgId && $0.friend?.peerID == peerID }
        )
        descriptor.fetchLimit = 1
        return ((try? modelContext.fetch(descriptor))?.isEmpty == false)
    }

    // MARK: - Header adapters
    //

    private static func messageHeader(from e: ConversationFrame) -> RatchetHeader {
        RatchetHeader(cid: e.cid, rk: e.rk, kemCt: e.kemCt, n: e.n, pn: e.pn)
    }

    /// The frame kind, for a log line.
    private func kindName(_ e: ConversationFrame) -> String {
        switch e.t {
        case .initiate: "init"
        case .message: "msg"
        case .receipt: "receipt"
        }
    }

    private static func initHeader(from e: ConversationFrame) -> RatchetInitHeader? {
        guard let ctId = e.ctId, let ctMt = e.ctMt, let rk = e.rk else { return nil }
        // A nil ctOt is the exhausted one-time pool (the decoder rejected mismatches).
        let ctOt = e.ctOt
        return RatchetInitHeader(ctId: ctId, ctMt: ctMt, ctOt: ctOt,
                                 otId: ctOt == nil ? nil : e.otId,
                                 rk: rk, cid: e.cid)
    }

    // MARK: - Presence

    /// A friend's retained presence flipped (MQTT `u/{id}/presence`).
    func setPresence(id: String, online: Bool) {
        guard let friend = friend(withID: id) else { return }
        friend.isOnline = online
        try? modelContext.save()
    }

    /// Marks everyone offline when our own connection drops.
    func clearAllPresence() {
        guard let profileId = currentProfile?.id else { return }
        let descriptor = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.profile?.id == profileId && $0.isOnline }
        )
        guard let friends = try? modelContext.fetch(descriptor) else { return }
        for friend in friends { friend.isOnline = false }
        try? modelContext.save()
    }
}
