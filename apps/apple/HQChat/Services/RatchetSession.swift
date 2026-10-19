// The double-ratchet state machine, driven over an injected KEM. Mirrors
// services/server/test/reference/protocol/ratchet.ts.
//
// Split from DoubleRatchet.swift for the same reason the TypeScript is split:
// that module stays pure and pinnable by cross-implementation vectors, and this
// one can be exercised with a stub KEM on any machine — the real HQC library is
// a native binary and the Swift test runner has no linkage to it.
//
// ── The shape of a session ──────────────────────────────────────────────────
// Roles are asymmetric only for the first message. The INITIATOR claims the
// responder's prekeys, derives root_0 plus its own first sending chain, and
// sends `init`. The RESPONDER decapsulates, derives the same pair as its
// receiving chain, and performs the first real ratchet step when it replies.
// After that the two are interchangeable.
//
// ── What is deliberately NOT here ───────────────────────────────────────────
// Nothing in this file authenticates the peer. That comes from `ssId` being
// encapsulated to a TOFU-pinned identity key, which the caller decides. A
// session built against an unpinned key is a session with whoever the server
// said it was.

import Foundation

/// The KEM this ratchet rides on. HQC in the app, a stub in tests.
protocol RatchetKem {
    func generateKeypair() throws -> (pk: Data, sk: Data)
    func encapsulate(_ pk: Data) throws -> (ct: Data, ss: Data)
    func decapsulate(sk: Data, ct: Data) throws -> Data
}

// MARK: - Persisted state

/// One direction's symmetric chain.
struct RatchetChain: Codable, Equatable {
    var ck: Data
    /// Next index this chain will produce or expect.
    var n: Int
}

struct SkippedMessageKey: Codable, Equatable {
    /// `DoubleRatchet.chainId` of the ratchet key whose chain produced it.
    var chain: String
    var n: Int
    var key: Data
}

/// Everything a conversation needs, JSON-encoded into the Keychain.
struct RatchetSessionState: Codable, Equatable {
    /// Protocol version. State that is not this is deleted rather than migrated
    /// — nothing here has shipped, so a re-handshake is cheaper and safer than a
    /// migration path nobody will ever exercise twice.
    var v: Int = RatchetSession.protocolVersion

    var root: Data
    /// My ratchet keypair. Peers encapsulate to `rkPub`; `rkSec` opens their step.
    var rkPub: Data
    var rkSec: Data
    /// The peer's advertised ratchet key. Nil until the initiator hears back.
    var peerRkPub: Data?
    var send: RatchetChain?
    var recv: RatchetChain?
    /// Length of the previous sending chain — the `pn` header field.
    var prevSendN: Int
    var skipped: [SkippedMessageKey]
    /// Chains already stepped into, most recent last. Without this, a replayed
    /// stepping frame is re-applied: `open` must read the header before the
    /// payload can authenticate it, and the replay still decapsulates because
    /// our ratchet secret only rotates when WE send. It would then recompute the
    /// root from the current root instead of the one that step advanced, and the
    /// two sides would diverge for good.
    var seenChains: [String]
    /// The handshake header, carried on EVERY outbound frame until we hear back
    /// from the peer. Nil on the responder side.
    ///
    /// Cleared on the first successful `open`, not on the first `seal`. Clearing
    /// it when we send would lose it whenever the publish failed or the send was
    /// retried — the retry would go out as a plain `msg` naming a session the
    /// peer had never been told about, undeliverable forever with nothing to say
    /// why. Receiving anything from them is the only proof they have the session.
    ///
    /// The cost is that the handshake ciphertexts (~43 kB) repeat on each message
    /// until they reply. That is the right trade: it is bounded by one reply, and
    /// the alternative silently drops conversations.
    var pendingInit: RatchetInitHeader?
    /// Messages sent on the current sending chain, for the step policy.
    var sentOnChain: Int
    /// When the current sending chain started, for the step policy.
    var chainStartedAt: Date
}

/// The per-message header. Every field is bound as AEAD additional data.
struct RatchetHeader: Equatable {
    /// `chainId` of the sender's current ratchet key — on EVERY message, because
    /// `n` restarts at 0 on each chain and a bare straggler would otherwise be
    /// read against the wrong one.
    var cid: String
    /// Present only on a step.
    var rk: Data?
    var kemCt: Data?
    var n: Int
    var pn: Int
}

/// What the initiator must put in an `init` frame besides the sealed payload.
///
/// Codable because it is PERSISTED inside the session until the first frame goes
/// out. Holding it only in memory would mean an app restart between opening a
/// session and sending left a session that exists locally but that the peer was
/// never told about — `hasSession` true, every subsequent message undeliverable,
/// and nothing anywhere saying why.
struct RatchetInitHeader: Codable, Equatable {
    var ctId: Data
    var ctMt: Data
    var ctOt: Data?
    var otId: Int?
    var rk: Data
    var cid: String
}

/// The peer's published bundle, as claimed from the directory.
struct PrekeyBundle {
    var identityPk: Data
    var mediumPk: Data
    /// Nil when the peer's one-time pool was exhausted.
    var oneTimePk: Data?
    var oneTimeId: Int?
}

/// My own prekey secrets, needed to answer an `init`.
struct PrekeySecrets {
    var identitySk: Data
    var mediumSk: Data
    /// Looked up by the `otId` the initiator echoed back.
    var oneTimeSk: (Int) -> Data?
}

// MARK: - Core

/// What to do with an inbound `init` when a session already exists.
///
/// Two situations hide behind "we already have a session" and they need opposite
/// answers, so the choice is made here — pure, and identically on both devices.
enum InitCollision: Equatable {
    /// No session yet: the ordinary responder path.
    case open
    /// We have heard from them, so they hold our session. An init now is a
    /// replay, and honouring it would let anyone wipe a conversation by
    /// re-sending an old frame.
    case ignoreReplay
    /// Both sides started at once and we hold the lower id. Keep ours; they
    /// will yield when ours arrives.
    case keepOurs
    /// Both sides started at once and we hold the higher id. Drop ours, adopt
    /// theirs, and re-send what they never received.
    case yieldToTheirs

    /// - Parameters:
    ///   - hasSession: whether a session already exists for this contact.
    ///   - heardFromThem: whether they have ever sent us anything on it —
    ///     `pendingInit == nil`. If they have not, they cannot be holding our
    ///     session, so a collision is a genuine simultaneous start rather than
    ///     a replay.
    ///   - myID / peerID: client ids. The lower one keeps its session. Same
    ///     ordering the conversation topic uses (friendshipHash sorts the pair),
    ///     so there is one rule in the system rather than two that could drift
    ///     apart — and because both sides compare the same two values, exactly
    ///     one of them yields.
    static func resolve(hasSession: Bool, heardFromThem: Bool,
                        myID: String, peerID: String) -> InitCollision {
        guard hasSession else { return .open }
        if heardFromThem { return .ignoreReplay }
        // Equal ids would mean talking to ourselves; nothing to converge on, and
        // keeping is the safe half (it changes no state).
        return myID < peerID ? .keepOurs : (myID == peerID ? .keepOurs : .yieldToTheirs)
    }
}

enum RatchetSession {

    /// Bumped whenever the on-disk shape or the KDFs change. State at any other
    /// version is discarded, not migrated.
    static let protocolVersion = 2

    /// How many retired chains to remember for replay rejection. A step only
    /// lands if its ciphertext still decapsulates under our CURRENT ratchet
    /// secret, and that rotates every time we send a step — so a replay older
    /// than this is already refused by the KEM. This covers the window where it
    /// is not.
    static let maxSeenChains = 64

    // MARK: Starting a session

    /// Initiator side: derive root_0 from the peer's bundle and open a sending
    /// chain, so the very first message is already ratcheted and can be sent
    /// while the peer is offline.
    ///
    /// Three encapsulations, each doing a different job:
    ///   - to the pinned IDENTITY key: authenticates the peer. Without it, a
    ///     server that substituted a prekey would be talking to us as them.
    ///   - to the MEDIUM-term prekey: forward secrecy with a rotation-length window.
    ///   - to a ONE-TIME prekey when one was available: forward secrecy that ends
    ///     the moment the responder consumes it.
    static func startAsInitiator(
        kem: RatchetKem,
        bundle: PrekeyBundle,
        now: Date = Date()
    ) throws -> (state: RatchetSessionState, header: RatchetInitHeader) {
        let id = try kem.encapsulate(bundle.identityPk)
        let mt = try kem.encapsulate(bundle.mediumPk)
        let ot = try bundle.oneTimePk.map { try kem.encapsulate($0) }

        let derived = DoubleRatchet.initRoot(ssId: id.ss, ssMt: mt.ss, ssOt: ot?.ss)
        let mine = try kem.generateKeypair()
        let header = RatchetInitHeader(
            ctId: id.ct, ctMt: mt.ct, ctOt: ot?.ct, otId: bundle.oneTimeId,
            rk: mine.pk, cid: DoubleRatchet.chainId(mine.pk)
        )

        let state = RatchetSessionState(
            root: derived.root,
            rkPub: mine.pk,
            rkSec: mine.sk,
            // Not the peer's prekey: that key is single-use and the responder may
            // have already dropped its secret. The peer advertises a real ratchet
            // key on its first reply, and only then can we step.
            peerRkPub: nil,
            send: RatchetChain(ck: derived.chain, n: 0),
            recv: nil,
            prevSendN: 0,
            skipped: [],
            seenChains: [],
            pendingInit: header,
            sentOnChain: 0,
            chainStartedAt: now
        )
        return (state, header)
    }

    /// Responder side: rebuilds the same root from an `init` frame and opens the
    /// matching receiving chain.
    ///
    /// Nil when a ciphertext does not decapsulate: a forged or corrupt frame, or an
    /// `otId` whose secret is already consumed (a duplicate `init`). A nil must not
    /// tear down an existing session, or a replayed `init` would reset a
    /// conversation.
    static func startAsResponder(
        kem: RatchetKem,
        secrets: PrekeySecrets,
        header: RatchetInitHeader,
        now: Date = Date()
    ) -> RatchetSessionState? {
        do {
            let ssId = try kem.decapsulate(sk: secrets.identitySk, ct: header.ctId)
            let ssMt = try kem.decapsulate(sk: secrets.mediumSk, ct: header.ctMt)

            var ssOt: Data?
            if let ctOt = header.ctOt {
                // Without the one-time secret the init cannot be answered as sent: a root
                // from two of the three secrets would disagree with the initiator's.
                guard let otId = header.otId, let sk = secrets.oneTimeSk(otId) else { return nil }
                ssOt = try kem.decapsulate(sk: sk, ct: ctOt)
            }

            let derived = DoubleRatchet.initRoot(ssId: ssId, ssMt: ssMt, ssOt: ssOt)
            let mine = try kem.generateKeypair()

            return RatchetSessionState(
                root: derived.root,
                rkPub: mine.pk,
                rkSec: mine.sk,
                peerRkPub: header.rk,
                send: nil,  // opened by the first step, taken when we reply
                recv: RatchetChain(ck: derived.chain, n: 0),
                prevSendN: 0,
                skipped: [],
                // The initiator's chain counts as entered: a replayed init must
                // not be able to re-derive it later as though it were a step.
                seenChains: [DoubleRatchet.chainId(header.rk)],
                pendingInit: nil,  // the responder answers, it does not initiate
                sentOnChain: 0,
                chainStartedAt: now
            )
        } catch {
            return nil
        }
    }

    // MARK: Sending

    /// Whether the next send should perform an asymmetric step.
    ///
    /// A step is only possible once the peer has advertised a ratchet key.
    /// Beyond that it is a cost decision (a step costs ~29 kB): step when the
    /// current chain has run long enough or lived long enough, and always when
    /// there is no sending chain at all — the responder's first reply, which is
    /// the moment the ratchet actually starts turning.
    static func shouldStep(_ state: RatchetSessionState, now: Date = Date()) -> Bool {
        guard state.peerRkPub != nil else { return false }
        guard state.send != nil else { return true }
        // "used at least once" — the half of the documented policy that was
        // never in the code. A chain that has sent nothing has nothing to rotate
        // away from, so stepping off it spends ~29 kB to move from one unused
        // chain to another.
        if state.sentOnChain == 0 { return false }
        if state.sentOnChain >= DoubleRatchet.ratchetMaxMessagesPerChain { return true }
        return now.timeIntervalSince(state.chainStartedAt) >= DoubleRatchet.ratchetMinStepInterval
    }

    /// Take the next sending key, stepping the ratchet first when policy says
    /// to. The returned header must travel with the ciphertext and be bound as
    /// its AEAD additional data.
    static func seal(
        kem: RatchetKem,
        state: inout RatchetSessionState,
        now: Date = Date()
    ) throws -> (key: Data, header: RatchetHeader, initHeader: RatchetInitHeader?) {
        var stepRk: Data?
        var stepCt: Data?

        if shouldStep(state, now: now), let peerRk = state.peerRkPub {
            let enc = try kem.encapsulate(peerRk)
            let next = DoubleRatchet.rootStep(root: state.root, ss: enc.ss)

            // A fresh keypair per step is the point: the old secret is dropped,
            // so a later compromise cannot open ciphertexts naming the old key.
            let mine = try kem.generateKeypair()
            state.root = next.root
            state.prevSendN = state.send?.n ?? 0
            state.send = RatchetChain(ck: next.chain, n: 0)
            state.rkPub = mine.pk
            state.rkSec = mine.sk
            state.sentOnChain = 0
            state.chainStartedAt = now
            stepRk = mine.pk
            stepCt = enc.ct
        }

        guard var send = state.send else {
            // Only reachable if a responder sends before it ever received, which
            // startAsResponder makes impossible: it always opens a recv chain
            // and sets peerRkPub, so shouldStep returns true above.
            throw RatchetSessionError.noSendingChain
        }

        let key = DoubleRatchet.messageKey(send.ck)
        let header = RatchetHeader(
            // Always the sender's CURRENT chain, stepping or not — this is what
            // lets the receiver tell which chain `n` counts within.
            cid: DoubleRatchet.chainId(state.rkPub),
            rk: stepRk,
            kemCt: stepCt,
            n: send.n,
            pn: state.prevSendN
        )
        send.ck = DoubleRatchet.chainNext(send.ck)
        send.n += 1
        state.send = send
        state.sentOnChain += 1
        // Deliberately NOT cleared here — see `pendingInit`.
        return (key, header, state.pendingInit)
    }

    // MARK: Receiving

    /// A receiving step computed from a header, not yet committed to the session.
    private struct PendingStep {
        var root: Data
        var peerRkPub: Data
        var recv: RatchetChain
        /// The chain entered, to remember once committed.
        var enteredCid: String
        /// Keys left on the retiring chain (up to `pn`), cached only once committed.
        var tail: (cid: String, keys: [(n: Int, key: Data)])?
    }

    /// Message key for an inbound header, or nil (a replay, a retired chain, a
    /// gap too large, or a payload that does not authenticate; none is an error).
    ///
    /// `verify` is the AEAD open and the only authenticator: HQC uses implicit
    /// rejection, so a forged step decapsulates to a pseudo-random secret without
    /// error. Everything is computed into locals and `state` is written only
    /// after `verify` passes, here rather than at call sites.
    static func open(
        kem: RatchetKem,
        state: inout RatchetSessionState,
        header: RatchetHeader,
        verify: (Data) -> Bool
    ) -> Data? {
        guard header.n >= 0, header.pn >= 0 else { return nil }
        guard header.cid.count == 32,
              header.cid.allSatisfy({ ("0"..."9").contains($0) || ("a"..."f").contains($0) })
        else { return nil }

        // Skipped keys first, so a late message resolves without touching live state.
        if let i = findSkipped(state, chain: header.cid, n: header.n) {
            return openSkipped(&state, at: i, verify: verify)
        }

        let currentCid = state.peerRkPub.map { DoubleRatchet.chainId($0) }
        var step: PendingStep?
        if header.cid != currentCid {
            guard let computed = computeStep(kem: kem, state: state, header: header, currentCid: currentCid) else {
                return nil
            }
            step = computed
        }

        guard let recv = step?.recv ?? state.recv, header.n >= recv.n else { return nil }
        // Nil for a gap past maxSkipped, refused without walking it.
        guard let walk = DoubleRatchet.walkChain(ck: recv.ck, fromN: recv.n, targetN: header.n),
              verify(walk.messageKey) else { return nil }

        if let step {
            state.root = step.root
            state.peerRkPub = step.peerRkPub
            if let tail = step.tail { cacheSkipped(&state, chain: tail.cid, keys: tail.keys) }
            rememberChain(&state, step.enteredCid)
        }
        cacheSkipped(&state, chain: header.cid, keys: walk.skipped)
        state.recv = RatchetChain(ck: walk.ck, n: walk.nextN)
        // Hearing from them proves they hold the session, so the init header stops
        // riding every frame.
        state.pendingInit = nil
        return walk.messageKey
    }

    /// A cached key for a skipped position, consumed only if it verifies, so a
    /// corrupt frame cannot burn the real message's key.
    private static func openSkipped(_ state: inout RatchetSessionState, at i: Int,
                                    verify: (Data) -> Bool) -> Data? {
        let key = state.skipped[i].key
        guard verify(key) else { return nil }
        state.skipped.remove(at: i)
        return key
    }

    /// The step a header asks for into a new chain, or nil unless it is a
    /// well-formed step to an unseen chain whose ciphertext decapsulates.
    private static func computeStep(kem: RatchetKem, state: RatchetSessionState,
                                    header: RatchetHeader, currentCid: String?) -> PendingStep? {
        guard let rk = header.rk, let kemCt = header.kemCt else { return nil }
        // `cid` must name the key it travels with, or the two sides could pick different chains.
        guard DoubleRatchet.chainId(rk) == header.cid else { return nil }
        // A retired chain is never re-entered (see `seenChains`).
        guard !state.seenChains.contains(header.cid) else { return nil }
        // Throws only on a wrong-sized ciphertext; anything else decapsulates.
        guard let ss = try? kem.decapsulate(sk: state.rkSec, ct: kemCt) else { return nil }

        // `pn` is attacker-chosen and caching evicts, so the tail of the retiring
        // chain is only computed here and cached after `verify`.
        var tail: (cid: String, keys: [(n: Int, key: Data)])?
        if let current = state.recv, let currentCid {
            let remaining = header.pn - current.n
            if remaining > 0, remaining <= DoubleRatchet.maxSkipped,
               let walked = DoubleRatchet.walkChain(ck: current.ck, fromN: current.n, targetN: header.pn - 1) {
                tail = (cid: currentCid, keys: walked.skipped + [(n: header.pn - 1, key: walked.messageKey)])
            }
        }

        let next = DoubleRatchet.rootStep(root: state.root, ss: ss)
        return PendingStep(root: next.root, peerRkPub: rk, recv: RatchetChain(ck: next.chain, n: 0),
                           enteredCid: header.cid, tail: tail)
    }

    // MARK: Skipped-key cache

    /// Index of a cached key, or nil. Deliberately does NOT remove it: the
    /// caller consumes it only once the payload has authenticated, so a corrupt
    /// frame at a skipped position cannot burn the key for the real message that
    /// belongs there.
    private static func findSkipped(_ state: RatchetSessionState, chain: String, n: Int) -> Int? {
        state.skipped.firstIndex(where: { $0.chain == chain && $0.n == n })
    }

    /// Cache keys skipped on the way to a delivered one, bounded by maxSkipped.
    ///
    /// Deliberately still a linear array rather than a dictionary keyed on
    /// "{chain}:{n}". Measured, a worst-case `findSkipped` over a FULL
    /// 2000-entry cache costs ~14 microseconds per inbound frame, while
    /// JSON-encoding that same cache into the Keychain — which happens on every
    /// save, and which an index does not help at all — costs ~392, twenty-eight
    /// times more. The index buys the small half of the win.
    ///
    /// It costs the persisted shape, which is not a fair trade: a change to
    /// `skipped` means bumping `protocolVersion`, and that DELETES the session
    /// rather than migrating it — with no recovery, because a re-`init` from a
    /// peer who has heard from you is refused as a replay. A 14-microsecond
    /// saving is not worth standing anywhere near that.
    private static func cacheSkipped(
        _ state: inout RatchetSessionState,
        chain: String,
        keys: [(n: Int, key: Data)]
    ) {
        for k in keys {
            state.skipped.append(SkippedMessageKey(chain: chain, n: k.n, key: k.key))
        }
        // Oldest first — the cache is append-ordered, so the head is the least
        // likely to still be in flight.
        if state.skipped.count > DoubleRatchet.maxSkipped {
            state.skipped.removeFirst(state.skipped.count - DoubleRatchet.maxSkipped)
        }
    }

    private static func rememberChain(_ state: inout RatchetSessionState, _ cid: String) {
        state.seenChains.append(cid)
        if state.seenChains.count > maxSeenChains {
            state.seenChains.removeFirst(state.seenChains.count - maxSeenChains)
        }
    }
}

enum RatchetSessionError: Error, LocalizedError {
    case noSendingChain

    var errorDescription: String? {
        switch self {
        case .noSendingChain:
            return "This conversation has no sending chain yet."
        }
    }
}
