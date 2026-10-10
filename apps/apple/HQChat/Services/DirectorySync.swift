import Foundation
import SwiftData

fileprivate func dlog(_ message: @autoclosure () -> String) {
    let text = message()
    Log.network.debug("\(text)")
}

/// Pulls the friend graph from the server into the local store: on sign-in, on
/// a timer, and after every mutation this client makes.
///
/// The directory carries client ids, `sha256(lowercase-hex(publicKey))`. Each
/// key is fetched once and verified against its id before it is pinned
/// (`Friend.pin(publicKeyHex:)`), so a server cannot substitute a key.
///
/// A changed key is a changed identity: a lookup by id misses, and the username
/// fallback detects that the old identity vanished and a new one appeared under
/// the same handle. The old row is kept read-only; the new one is a separate
/// contact that needs its own verification.
@MainActor
final class DirectorySync {

    private let api: APIClient
    private let modelContext: ModelContext
    private let profileManager: ProfileManager?

    init(api: APIClient, modelContext: ModelContext, profileManager: ProfileManager?) {
        self.api = api
        self.modelContext = modelContext
        self.profileManager = profileManager
    }

    private var currentProfile: Profile? { profileManager?.currentProfile }

    /// Fetches friends, invites and blocks and reconciles them into SwiftData.
    /// Returns the friends that now hold a client id, so the caller can subscribe
    /// to their topics.
    @discardableResult
    func sync() async throws -> [Friend] {
        guard let profile = currentProfile else { return [] }
        let profileId = profile.id

        let friends = try await api.getFriends()
        let invites = try await api.getInvites()
        let blockedIDs = await blockList()
        // Every identity the server listed, in either direction: one it still
        // lists has not vanished, whatever its display name collides with.
        let serverIDs = Set(friends.map { $0.id }).union(invites.map { $0.id })

        var known: [Friend] = []
        for dto in friends {
            guard let row = upsert(id: dto.id, username: label(dto.username, dto.id),
                                   status: .accepted, profileId: profileId,
                                   serverIDs: serverIDs) else { continue }
            applyTopics(dto, to: row)
            known.append(row)
        }
        for invite in invites {
            if let row = upsert(id: invite.id, username: label(invite.username, invite.id),
                                status: .inviteReceived, profileId: profileId,
                                serverIDs: serverIDs) {
                known.append(row)
            }
        }
        // Without the block list, removals are skipped: a blocked contact is
        // absent from /friends, and removal would delete its conversation.
        if let blockedIDs {
            reconcileBlocks(blockedIDs: blockedIDs, profileId: profileId)
            reconcileRemovals(serverIDs: serverIDs, profileId: profileId)
        }
        // Saved only when changed: this runs on a timer, and an empty save still
        // churns the views that list conversations.
        if modelContext.hasChanges { try? modelContext.save() }

        // A key never changes for a given id, so this fetches once per contact ever.
        await fetchMissingKeys(for: known)
        if modelContext.hasChanges { try? modelContext.save() }

        NotificationService.shared.refreshCounts(modelContext: modelContext, profileID: profileId)
        return known
    }

    /// The blocked ids, or nil when the server did not answer (never flattened to
    /// "none blocked", which would let removals delete a blocked contact).
    private func blockList() async -> Set<String>? {
        do {
            return Set(try await api.getBlocked())
        } catch {
            dlog("[DirectorySync] ⚠️ could not read the block list (\(error)) — skipping removals this cycle")
            return nil
        }
    }

    /// The friendship's topic ids, written whenever they change (a re-friend
    /// mints new ones) and not otherwise, since an unchanged write still dirties
    /// the context.
    private func applyTopics(_ dto: APIClient.FriendDTO, to row: Friend) {
        guard FriendTopics(convoID: dto.convo_id, handshakeID: dto.handshake_id) != nil else { return }
        if row.convoTopicID != dto.convo_id { row.convoTopicID = dto.convo_id }
        if row.handshakeTopicID != dto.handshake_id { row.handshakeTopicID = dto.handshake_id }
    }

    /// Fetch and verify the identity key for any contact we do not have one for.
    ///
    /// Best-effort and per-contact: a server that will not answer for one person
    /// must not stop the rest of the sync, and a contact without a key is a
    /// perfectly ordinary state — the session simply cannot open until it has one.
    private func fetchMissingKeys(for friends: [Friend]) async {
        for friend in friends where !friend.hasPinnedKey && !friend.peerID.isEmpty {
            let id = friend.peerID
            let served: String?
            do { served = try await api.peerKey(id: id) } catch {
                dlog("[DirectorySync] could not fetch \(friend.username)'s key: \(error)")
                ProtocolLog.record(.dropped(stage: "key-fetch", peerID: id,
                                            reason: "GET /peer/{id}/key failed"))
                continue
            }
            guard let served else {
                dlog("[DirectorySync] the server knows no key for \(friend.username) (\(id.prefix(8))…)")
                ProtocolLog.record(.dropped(stage: "key-fetch", peerID: id,
                                            reason: "server knows no key for this id"))
                continue
            }
            if friend.pin(publicKeyHex: served) {
                dlog("[DirectorySync] 🔑 pinned \(friend.username)'s key, verified against their id")
                ProtocolLog.record(.keyFetched(peer: id, verified: true))
                ProtocolLog.record(.keyPinned(peer: id, source: .directory))
            } else {
                ProtocolLog.record(.keyFetched(peer: id, verified: false))
                ProtocolLog.record(.keyRejected(peer: id,
                                                reason: "served key does not hash to the id"))
                // Loud, and refused. Either the server is lying or its directory
                // and its key store disagree; both mean this key must not be
                // encrypted to. There is nothing for the user to decide here —
                // the arithmetic already decided.
                dlog("[DirectorySync] 🚨 the key served for \(friend.username) does NOT hash to "
                     + "their id (\(id.prefix(8))…) — refusing it")
            }
        }
    }

    /// What to call a peer who has not claimed a handle.
    ///
    /// Their ID, shortened — not a shared word like "Anonymous". A placeholder
    /// every nameless account has in common would collide in `upsert`'s
    /// username fallback below, and the fallback is exactly how a re-keyed
    /// contact is detected: two nameless peers would read as one of them having
    /// vanished. The server sends null for these rather than deciding for us.
    private func label(_ username: String?, _ id: String) -> String {
        guard let username, !username.isEmpty else { return String(id.prefix(8)) }
        return username
    }

    /// Find (by id, then by username for rows created locally before the id was
    /// known) or create the row, and apply the server's view of it.
    // Not `private`, like the two reconcile passes below: the vanished-marking
    // branch decides whether a contact is shown as an impersonation warning, and
    // that is worth driving rather than reading.
    func upsert(id: String, username: String,
                        status: Friend.InviteStatus, profileId: UUID,
                        serverIDs: Set<String>) -> Friend? {
        guard PeerID.isWellFormed(id) else { return nil }

        let byID = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.peerID == id && $0.profile?.id == profileId }
        )
        if let existing = try? modelContext.fetch(byID).first {
            if existing.username != username { existing.username = username }
            // An identity that is listed again is not vanished. This is the
            // benign case the state has to survive: a transient sync that did
            // not list someone, followed by one that does.
            if existing.isVanished { existing.vanishedAt = nil }
            advance(existing, to: status)
            return existing
        }

        // A row we created ourselves when the invite was sent carries a username
        // and no id; this is where it gets its real one. Only rows that are still
        // waiting — one that already HAS an id is a different identity, handled
        // below.
        let byName = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.username == username && $0.profile?.id == profileId }
        )
        let sameName = (try? modelContext.fetch(byName)) ?? []

        if let waiting = sameName.first(where: { $0.isPending }) {
            waiting.peerID = id
            advance(waiting, to: status)
            dlog("[DirectorySync] ✅ \(username) answered — id \(id.prefix(8))…")
            return waiting
        }

        // Same handle, a different identity, and the old id is absent from the list: the
        // contact we had is gone. It is marked vanished, never merged (that would
        // carry a verification the new key never earned) nor deleted (that would
        // lose the user's messages). Requiring the old id to be absent from
        // `serverIDs` keeps a name collision from triggering this.
        for stale in sameName
        where !stale.isPending && !stale.isVanished && !stale.isBlocked
              && !serverIDs.contains(stale.peerID) {
            stale.vanishedAt = Date()
            dlog("[DirectorySync] ⚠️ \(username)'s identity changed — \(stale.peerID.prefix(8))… "
                 + "is gone, \(id.prefix(8))… is new")
        }

        let friend = Friend(username: username, peerID: id,
                            isOnline: false,
                            inviteStatus: status, profile: currentProfile)
        modelContext.insert(friend)
        dlog("[DirectorySync] ✅ added \(username)")
        return friend
    }

    /// An accepted friendship never regresses to "invite received" because a
    /// stale invite row is still listed.
    private func advance(_ friend: Friend, to status: Friend.InviteStatus) {
        if friend.inviteStatus == .accepted { return }
        friend.inviteStatus = status
    }

    /// Adopt the server's block list, in both directions.
    ///
    /// The user may have blocked somebody from another device, and may have
    /// unblocked them there too. Both have to arrive, and the first one has to
    /// arrive BEFORE `reconcileRemovals` runs — which is why this is a separate
    /// pass rather than something folded into `upsert`: a blocked peer is not in
    /// `/friends`, so `upsert` is never called for them at all.
    // Not `private`: OrchestratorTests drives both reconcile passes directly.
    // The alternative is testing a history-destroying deletion only through a
    // full HTTP round trip, which is the kind of coverage that quietly stops
    // existing.
    func reconcileBlocks(blockedIDs: Set<String>, profileId: UUID) {
        let all = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.profile?.id == profileId }
        )
        guard let rows = try? modelContext.fetch(all) else { return }
        for row in rows where !row.isPending {
            let blocked = blockedIDs.contains(row.peerID)
            if blocked && !row.isBlocked {
                row.blockedAt = Date()
                dlog("[DirectorySync] 🚫 \(row.username) is blocked (from another device)")
            } else if !blocked && row.isBlocked {
                row.blockedAt = nil
                dlog("[DirectorySync] ✅ \(row.username) is no longer blocked")
            }
        }
    }

    /// Drops local rows the server does not list: an unfriend from the other side,
    /// or an invite withdrawn or declined.
    func reconcileRemovals(serverIDs: Set<String>, profileId: UUID) {
        let all = FetchDescriptor<Friend>(
            predicate: #Predicate<Friend> { $0.profile?.id == profileId }
        )
        guard let rows = try? modelContext.fetch(all) else { return }
        for row in rows {
            // Rows still waiting on an id (an invite we just sent) are ours, not
            // the server's, and must survive a sync.
            if row.isPending { continue }
            if serverIDs.contains(row.peerID) { continue }
            if row.inviteStatus == .inviteSent { continue }
            // A vanished identity is ALREADY absent from the server — that is
            // what vanished means. Deleting it here would undo the whole point:
            // the history is kept, read-only, and only the user removes it.
            if row.isVanished { continue }
            // Same reasoning, different cause. A blocked contact is absent
            // because the user made them absent; deleting the conversation they
            // blocked someone over is the opposite of what they asked for.
            // Unblocking clears the flag and this row becomes ordinary again —
            // at which point, still absent from the directory, it is removed.
            if row.isBlocked { continue }
            dlog("[DirectorySync] 🗑️ \(row.username) no longer on the server — removing")
            row.clearAESKeys()          // purge Keychain key material
            modelContext.delete(row)
        }
    }
}
