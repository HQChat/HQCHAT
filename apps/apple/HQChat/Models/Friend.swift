import Foundation
import SwiftData

/// HQC-256 public key size, in bytes (`HQCService.PUBLIC_KEY_BYTES`). Spelled
/// out here so the model does not have to import the native library just to know
/// what a complete key looks like.
let HQCPublicKeySize = 7237

@Model
final class Friend {
    var username: String

    /// The contact's CLIENT ID — `sha256(lowercase-hex(publicKey))`, 64 hex
    /// characters. This is what the directory, the per-user topics and the
    /// envelope's `sender` all name them by.
    ///
    /// Empty is a real state: a row created when an invite is SENT knows only a
    /// username, because the server has not told us who that is yet. `isPending`
    /// below is that state, and it is the one thing a sync must not delete.
    var peerID: String = ""

    /// The friendship's topic ids, from `/friends`: the conversation is
    /// `cv/{convoTopicID}` and the handshake `hs/{handshakeTopicID}`. Random per
    /// friendship and handed only to its two members — knowing them is the
    /// broker's whole check on a conversation — so they cannot be derived and
    /// are nil until a directory sync delivers them. A re-friend mints new ones;
    /// the sync overwrites these, and the old topics go quiet.
    ///
    /// Optional, which is all SwiftData's lightweight migration needs.
    var convoTopicID: String?
    var handshakeTopicID: String?

    /// Both topics, or nil before a sync has named them.
    var topics: FriendTopics? {
        FriendTopics(convoID: convoTopicID, handshakeID: handshakeTopicID)
    }

    /// The contact's identity public key, 7237 bytes — empty until fetched.
    ///
    /// The directory ships IDS now (64 characters per friend rather than 14474,
    /// every sixty seconds), so the key arrives separately: once, from
    /// `GET /peer/{id}/key` at friend-add, or on the `init` frame that opens a
    /// session. Either way it is CHECKED against `peerID` before it is stored —
    /// see `pin(publicKey:)`.
    var publicKey: Data
    var isOnline: Bool
    var inviteStatusRaw: String?  // Store as optional String for migration compatibility

    // MARK: - Key authenticity
    //
    // The server delivers friends' keys, so a malicious or compromised server
    // could hand each side its own and MITM the "E2E". Two things stop it:
    //
    //   * the id is a COMMITMENT to the key — `PeerID.matches` — so a key that
    //     does not hash to the id we were given is refused, never pinned. TOFU
    //     narrows to "trust the id you were first given"; everything after that
    //     is arithmetic;
    //   * the safety number, which the user compares out of band to check the
    //     id itself. It hashes the raw KEY BYTES, deliberately: it verifies key
    //     material, not names.
    //
    // What is NOT here any more is `pendingKeyHex`. It modelled an in-place
    // re-key — "the server says this contact's key changed; accept it?" — and
    // that state cannot exist now. A new key is a new id is a new contact. See
    // `vanishedAt`.
    var keyVerified: Bool?          // nil/false = pinned but not user-verified

    /// True once the user confirmed the safety number out-of-band.
    var isKeyVerified: Bool { keyVerified == true }

    /// When this identity stopped being reachable, or nil while it still is.
    ///
    /// Set when the server stops listing this id while the same username appears
    /// under a different one: the person reinstalled, reset or moved device, and
    /// the old identity is gone. Nothing can be sent here again.
    ///
    /// The row is kept read-only, never deleted or merged into the new identity:
    /// the history is the user's, and merging would carry over a verification the
    /// new key never earned. The new identity arrives as a separate contact.
    ///
    /// ⚠️ This is also what an impersonation looks like, and the UI copy says so.
    var vanishedAt: Date?

    /// True once this identity is gone. A vanished contact is read-only.
    var isVanished: Bool { vanishedAt != nil }

    /// When the user blocked this contact, or nil while they have not.
    ///
    /// A block is an unfriend PLUS a durable server row that outlives it
    /// (006_reports.sql), and this is the local half of the same idea. It has to
    /// exist for a reason that is easy to miss: blocking tears the friendship
    /// down, so the peer disappears from `/friends` — and absence from the
    /// directory is exactly what `DirectorySync.reconcileRemovals` reads as
    /// "delete this row, purge its Keychain material". Without this flag,
    /// blocking somebody destroys the conversation the user blocked them OVER,
    /// on the next sixty-second poll, with no way to get it back.
    ///
    /// Like `vanishedAt`, the row is KEPT and read-only. Unlike `vanishedAt`,
    /// the user chose it and the user can undo it.
    var blockedAt: Date?

    /// True once the user has blocked this contact. A blocked contact is
    /// read-only, and nothing may be sent to it.
    var isBlocked: Bool { blockedAt != nil }

    /// Nothing can be sent to this contact, whichever of the two reasons applies.
    /// Call sites that only need "is this conversation writable" should ask this
    /// rather than testing the two flags, which is how one of them gets missed.
    var isReadOnly: Bool { isVanished || isBlocked }

    /// A row we created when an invite was sent, before the server told us who
    /// the recipient is. It holds a username and nothing else.
    var isPending: Bool { peerID.isEmpty }

    /// True once we hold this contact's identity key — the thing a session needs.
    var hasPinnedKey: Bool { publicKey.count == HQCPublicKeySize }

    /// Adopt a public key for this contact, if and only if it is the key their
    /// id names.
    ///
    /// The single place a key is written. Returns false — and stores nothing —
    /// when the key does not hash to `peerID`, which is what makes a substituted
    /// key impossible for the server rather than merely unlikely.
    @discardableResult
    func pin(publicKeyHex hex: String) -> Bool {
        guard !peerID.isEmpty,
              PeerID.matches(publicKeyHex: hex, id: peerID),
              let data = Data(hexString: hex), data.count == HQCPublicKeySize
        else { return false }
        if publicKey != data { publicKey = data }
        return true
    }

    // MARK: - AES key material (Keychain-backed, NOT stored in the database)
    // These look like normal properties to all call sites, but SwiftData does
    // not persist computed properties — the bytes live in the Keychain via
    // AESKeyStore, keyed by the friend's public key. This keeps decryption keys
    // out of the plaintext SwiftData store.

    /// Keychain account for one piece of this friend's key material.
    ///
    /// Namespaced by the *owning profile* as well as the peer: the shared
    /// channel key is a property of the pair, so two of our profiles talking to
    /// the same person hold two different keys. Keyed on the peer alone (as it
    /// was), the second profile's handshake silently overwrote the first's and
    /// broke its history.
    ///
    /// The peer half is the CLIENT ID. It was `publicKeyHex` — which this file's
    /// own comment complained about, since a 7237-byte HQC key makes a
    /// 14k-character Keychain account string. It is 64 characters now.
    ///
    /// Renaming an account orphans whatever is stored under the old one.
    private func aesAccount(_ suffix: String) -> String {
        Self.aesAccount(profileID: profile?.id, peerID: peerID, suffix: suffix)
    }

    /// The same account string, callable without a live `Friend`.
    static func aesAccount(profileID: UUID?, peerID: String, suffix: String) -> String {
        "aes.\(profileID?.uuidString ?? "noprofile").\(peerID).\(suffix)"
    }

    /// The suffixes of a friend's key material: one serialised ratchet session
    /// (root, both chains, ratchet key pair and skipped-key cache).
    static let aesSuffixes = ["ratchet"]

    /// The double-ratchet session with this friend, JSON-encoded in the Keychain.
    ///
    /// Absent means no session, the only meaning of "not set up": a session is
    /// derived in one step from a claimed prekey bundle.
    ///
    /// State at a different protocol version is discarded, not migrated; the next
    /// message re-handshakes.
    var ratchetSession: RatchetSessionState? {
        get {
            guard let data = AESKeyStore.get(aesAccount("ratchet")),
                  let session = try? JSONDecoder().decode(RatchetSessionState.self, from: data)
            else { return nil }
            guard session.v == RatchetSession.protocolVersion else {
                AESKeyStore.delete(aesAccount("ratchet"))
                return nil
            }
            return session
        }
        set {
            AESKeyStore.set(newValue.flatMap { try? JSONEncoder().encode($0) },
                            account: aesAccount("ratchet"))
        }
    }

    /// Whether messages can flow. Derived, not stored: v1 carried a
    /// `hasSecureChannel` column that had to be kept in step with the Keychain by
    /// hand, and the two could disagree — a restored database with no Keychain
    /// showed contacts as ready and then dropped every message.
    var hasSession: Bool { ratchetSession != nil }

    /// Remove this friend's AES key material from the Keychain (call on removal).
    func clearAESKeys() {
        for suffix in Self.aesSuffixes { AESKeyStore.delete(aesAccount(suffix)) }
    }
    
    @Relationship(deleteRule: .cascade) var messages: [Message]?

    /// A contact who is ready but has never been written to: a session opens on
    /// demand from the peer's published prekeys when the first message is sent,
    /// so nothing is "setting up".
    var isReadyButUnopened: Bool {
        !hasSession && hasPinnedKey && !isVanished && (messages?.isEmpty ?? true)
    }
    var profile: Profile?
    
    enum InviteStatus: String, Codable {
        case none = "none"              // No invite sent/received
        case inviteSent = "invite_sent" // We sent an invite (pending)
        case inviteReceived = "invite_received" // We received an invite (pending acceptance)
        case accepted = "accepted"      // Friend request accepted, friendship established
    }
    
    // Computed property for inviteStatus with default value
    var inviteStatus: InviteStatus {
        get {
            guard let raw = inviteStatusRaw, let status = InviteStatus(rawValue: raw) else {
                return .none
            }
            return status
        }
        set {
            inviteStatusRaw = newValue.rawValue
        }
    }
    
    init(username: String,
         peerID: String = "",
         publicKey: Data = Data(),
         isOnline: Bool = false,
         inviteStatus: InviteStatus = .none,
         profile: Profile? = nil) {
        self.username = username
        self.peerID = peerID
        self.publicKey = publicKey
        self.isOnline = isOnline
        self.inviteStatusRaw = inviteStatus.rawValue
        self.messages = []
        self.profile = profile
    }

    /// Get public key as hex string. Empty when the key has not been fetched.
    var publicKeyHex: String {
        return publicKey.hexString
    }
    
    /// Check if invite is pending (sent or received)
    var isInvitePending: Bool {
        return inviteStatus == .inviteSent || inviteStatus == .inviteReceived
    }
}

