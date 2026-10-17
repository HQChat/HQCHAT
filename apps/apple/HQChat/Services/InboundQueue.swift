import Foundation
import SwiftData

/// Inbound frames between arrival and opening.
///
/// Admitting needs no key: a frame is stored as it arrived (`PendingFrame`). It
/// is opened once the ratchet state can be read, which needs the user, so a
/// frame that arrives while locked waits here and the backlog drains on unlock.
///
/// Each sender drains on its own task, in arrival order (the order the ratchet
/// must see), yielding between frames. So a backlog never holds up the UI, a
/// frame arriving mid-drain joins the tail of its sender's queue rather than
/// waiting for the whole backlog, and one sender's backlog never delays
/// another's live messages.
@MainActor
final class InboundQueue {

    private let modelContext: ModelContext
    /// Whether frames can be opened right now.
    private let canProcess: () -> Bool
    /// Opens one frame. True when the frame is done with (opened or dropped,
    /// and deleted); false to stop this sender's drain and retry on the next
    /// kick, leaving the frame queued.
    var process: ((PendingFrame) async -> Bool)?
    /// Raised when a sender's queue stops draining, for the badge count.
    var onDrained: (() -> Void)?

    private var draining: [String: Task<Void, Never>] = [:]
    private var nextSeq: Int

    init(modelContext: ModelContext, canProcess: @escaping () -> Bool) {
        self.modelContext = modelContext
        self.canProcess = canProcess
        var last = FetchDescriptor<PendingFrame>(sortBy: [SortDescriptor(\.seq, order: .reverse)])
        last.fetchLimit = 1
        nextSeq = ((try? modelContext.fetch(last))?.first?.seq ?? -1) + 1
    }

    /// Stores a frame. False when the same frame is already queued (a broker
    /// re-delivery), in which case nothing is stored.
    @discardableResult
    func admit(profileID: UUID, senderID: String, topic: String, raw: Data,
               kind: PendingFrame.Kind, dedupeKey: String) -> Bool {
        let pid: UUID? = profileID
        var existing = FetchDescriptor<PendingFrame>(predicate: #Predicate {
            $0.profileID == pid && $0.senderID == senderID && $0.dedupeKey == dedupeKey
        })
        existing.fetchLimit = 1
        if (try? modelContext.fetchCount(existing)) ?? 0 > 0 { return false }

        modelContext.insert(PendingFrame(profileID: profileID, senderID: senderID, topic: topic,
                                         raw: raw, kind: kind, dedupeKey: dedupeKey, seq: nextSeq))
        nextSeq += 1
        try? modelContext.save()
        return true
    }

    /// Starts draining `senderID`'s frames unless a drain already runs; a
    /// running drain picks up what was just admitted.
    func kick(profileID: UUID, senderID: String) {
        let key = Self.key(profileID, senderID)
        guard draining[key] == nil, canProcess() else { return }
        draining[key] = Task { [weak self] in
            await self?.drain(profileID: profileID, senderID: senderID)
        }
    }

    /// Starts draining every sender with queued frames: after an unlock, a
    /// reconnect or a profile switch.
    func kickAll(profileID: UUID) {
        guard canProcess() else { return }
        let pid: UUID? = profileID
        let queued = (try? modelContext.fetch(FetchDescriptor<PendingFrame>(
            predicate: #Predicate { $0.profileID == pid }))) ?? []
        for sender in Set(queued.map(\.senderID)) {
            kick(profileID: profileID, senderID: sender)
        }
    }

    /// Waits for every running drain to finish. Tests only need this; the app
    /// never waits on a backlog.
    func waitUntilIdle() async {
        while let task = draining.values.first {
            await task.value
        }
    }

    /// Frames queued for a profile that may carry an unread message.
    static func unopenedMessageCount(modelContext: ModelContext, profileID: UUID) -> Int {
        let pid: UUID? = profileID
        let initiate = PendingFrame.Kind.initiate.rawValue
        let message = PendingFrame.Kind.message.rawValue
        let descriptor = FetchDescriptor<PendingFrame>(predicate: #Predicate {
            $0.profileID == pid && ($0.kindRaw == initiate || $0.kindRaw == message)
        })
        return (try? modelContext.fetchCount(descriptor)) ?? 0
    }

    // MARK: - Draining

    private func drain(profileID: UUID, senderID: String) async {
        let key = Self.key(profileID, senderID)
        // No suspension between finding the queue empty and leaving `draining`,
        // so a frame admitted meanwhile either is found here or kicks a new drain.
        while canProcess(), let frame = oldest(profileID: profileID, senderID: senderID),
              let process {
            guard await process(frame) else { break }
            await Task.yield()
        }
        draining[key] = nil
        onDrained?()
    }

    private func oldest(profileID: UUID, senderID: String) -> PendingFrame? {
        let pid: UUID? = profileID
        var descriptor = FetchDescriptor<PendingFrame>(
            predicate: #Predicate { $0.profileID == pid && $0.senderID == senderID },
            sortBy: [SortDescriptor(\.seq)]
        )
        descriptor.fetchLimit = 1
        return try? modelContext.fetch(descriptor).first
    }

    private static func key(_ profileID: UUID, _ senderID: String) -> String {
        "\(profileID.uuidString)/\(senderID)"
    }
}
