import Foundation
import HQChatCore

/// One request to the home server. Returns status 0 when the server could not
/// be reached, which the engine reads as unreachable.
public protocol HTTPPerformer: Sendable {
    func perform(method: HQChatCore.Method, url: URL, bearer: String?, body: Data) async -> (status: UInt16, body: Data)
}

/// An open connection, as the engine sees it: bytes out, and a close.
public protocol ByteConnection: Sendable {
    func write(_ data: Data)
    func close()
}

/// What a connection reports back. Each closure may be called from any thread.
public struct ConnectionEvents: Sendable {
    public let opened: @Sendable () -> Void
    public let received: @Sendable (Data) -> Void
    /// The peer or the network closed it; never called for a `close()` the shell asked for.
    public let closed: @Sendable (_ failure: String?) -> Void

    public init(
        opened: @escaping @Sendable () -> Void,
        received: @escaping @Sendable (Data) -> Void,
        closed: @escaping @Sendable (_ failure: String?) -> Void
    ) {
        self.opened = opened
        self.received = received
        self.closed = closed
    }
}

/// Opens the engine's connections: raw TCP for hqn/1, a pinned WebSocket for WSS.
public protocol ConnectionFactory: Sendable {
    func open(_ endpoint: Endpoint, events: ConnectionEvents) -> any ByteConnection
}

/// Carries out the core Engine's effects and hands every effect to the app.
///
/// The engine decides everything (sign-in, the friend graph, the broker
/// session, the ratchet); the shell only does what it is told: HTTP requests,
/// opening, writing and closing the broker connection, waking the engine at
/// its timer, and asking for the unlock when it needs the device key. Engine
/// calls are synchronous and thread-safe; the actor keeps the shell's own
/// state (open connections, the timer) consistent.
public actor CoreShell {
    public let engine: Engine
    private let baseURL: URL
    private let http: any HTTPPerformer
    private let connections: any ConnectionFactory
    private let clock: @Sendable () -> Int64
    private let onEffect: @Sendable (Effect) -> Void
    private let askToUnlock: @Sendable (UnlockReason) async -> Bool
    private var open: [UInt64: any ByteConnection] = [:]
    private var timer: Task<Void, Never>?

    /// - Parameters:
    ///   - askToUnlock: prompts the user (Face ID, Touch ID, the passcode) so
    ///     the vault can use the device key; true to go ahead with the unlock.
    ///   - onEffect: every effect, after the shell carried out its part; the
    ///     app updates its UI from these (messages, statuses, friends, …).
    public init(
        engine: Engine,
        baseURL: URL,
        http: any HTTPPerformer,
        connections: any ConnectionFactory,
        clock: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) },
        askToUnlock: @escaping @Sendable (UnlockReason) async -> Bool,
        onEffect: @escaping @Sendable (Effect) -> Void
    ) {
        self.engine = engine
        self.baseURL = baseURL
        self.http = http
        self.connections = connections
        self.clock = clock
        self.askToUnlock = askToUnlock
        self.onEffect = onEffect
    }

    /// Signs in and connects, or asks for the unlock first.
    public func start(network: NetworkInfo) {
        let now = clock()
        handle(engine.start(now: now, network: network))
    }

    /// The network path changed (Wi-Fi to cellular, a VPN, …).
    public func networkChanged(_ network: NetworkInfo) {
        let now = clock()
        handle(engine.onNetworkChanged(network: network, now: now))
    }

    /// Runs a user command (send, invite, accept, …) and carries out its effects.
    /// Errors (locked, not a friend, …) go back to the caller.
    @discardableResult
    public func perform(_ command: (Engine, Int64) throws -> [Effect]) rethrows -> [Effect] {
        let effects = try command(engine, clock())
        handle(effects)
        return effects
    }

    /// Closes every connection and stops the timer; the engine keeps its state.
    public func stop() {
        timer?.cancel()
        timer = nil
        for c in open.values { c.close() }
        open.removeAll()
    }

    // MARK: - Effects

    private func handle(_ effects: [Effect]) {
        for effect in effects {
            carryOut(effect)
            onEffect(effect)
        }
    }

    private func carryOut(_ effect: Effect) {
        switch effect {
        case let .http(req, method, path, authorization, body):
            request(req, method: method, path: path, bearer: authorization, body: body)
        case let .open(conn, endpoint):
            connect(conn, endpoint)
        case let .write(conn, bytes):
            open[conn]?.write(bytes)
        case let .close(conn):
            // The engine closed it: no onClosed goes back.
            open.removeValue(forKey: conn)?.close()
        case let .timer(at):
            schedule(at)
        case let .needUnlock(reason):
            Task { await self.unlock(reason) }
        default:
            break
        }
    }

    private func request(_ req: UInt64, method: HQChatCore.Method, path: String, bearer: String?, body: Data) {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            return deliver { $0.onHttp(req: req, status: 0, body: Data(), now: $1) }
        }
        let http = self.http
        Task {
            let (status, answer) = await http.perform(method: method, url: url, bearer: bearer, body: body)
            self.deliver { $0.onHttp(req: req, status: status, body: answer, now: $1) }
        }
    }

    private func connect(_ conn: UInt64, _ endpoint: Endpoint) {
        let events = ConnectionEvents(
            opened: { Task { await self.opened(conn) } },
            received: { bytes in Task { await self.received(conn, bytes) } },
            closed: { failure in Task { await self.closed(conn, failure) } }
        )
        open[conn] = connections.open(endpoint, events: events)
    }

    private func opened(_ conn: UInt64) {
        guard open[conn] != nil else { return }
        deliver { $0.onOpened(conn: conn, now: $1) }
    }

    private func received(_ conn: UInt64, _ bytes: Data) {
        guard open[conn] != nil else { return }
        deliver { $0.onBytes(conn: conn, bytes: bytes, now: $1) }
    }

    private func closed(_ conn: UInt64, _ failure: String?) {
        guard open.removeValue(forKey: conn) != nil else { return }
        let reason: CloseReason = failure.map { .failed(message: $0) } ?? .remote
        deliver { $0.onClosed(conn: conn, reason: reason, now: $1) }
    }

    private func schedule(_ at: Int64) {
        timer?.cancel()
        let wait = max(0, at - clock())
        timer = Task {
            try? await Task.sleep(nanoseconds: UInt64(wait) * 1_000_000)
            guard !Task.isCancelled else { return }
            self.tick()
        }
    }

    private func tick() {
        deliver { $0.tick(now: $1) }
    }

    private func unlock(_ reason: UnlockReason) async {
        guard await askToUnlock(reason) else { return }
        // A vault that still refuses surfaces again as needUnlock; nothing to do here.
        if let effects = try? engine.unlock(now: clock()) { handle(effects) }
    }

    private func deliver(_ result: (Engine, Int64) -> [Effect]) {
        handle(result(engine, clock()))
    }
}
