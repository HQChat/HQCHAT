import Foundation
import HQChatCore
import Network

/// HTTP through a URLSession the app configured (its TLS pinning delegate).
public struct URLSessionHTTP: HTTPPerformer {
    private let session: URLSession
    private let timeout: TimeInterval

    public init(session: URLSession, timeout: TimeInterval = 15) {
        self.session = session
        self.timeout = timeout
    }

    public func perform(method: HQChatCore.Method, url: URL, bearer: String?, body: Data) async -> (status: UInt16, body: Data) {
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.httpMethod = method == .get ? "GET" : "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let bearer { request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
        if method != .get { request.httpBody = body }
        do {
            let (data, response) = try await session.data(for: request)
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            return (UInt16(clamping: code), data)
        } catch {
            // Unreachable, refused by the pinning, or timed out: status 0.
            return (0, Data())
        }
    }
}

/// The engine's connections on the platform: raw TCP through Network.framework
/// for hqn/1 (the core speaks Noise over it and pins the gateway's key itself),
/// and a URLSession WebSocket for WSS, on the app's pinned session.
public struct PlatformConnections: ConnectionFactory {
    private let webSocketSession: URLSession
    private let queue = DispatchQueue(label: "hqchat.core-shell.connections")

    public init(webSocketSession: URLSession) {
        self.webSocketSession = webSocketSession
    }

    public func open(_ endpoint: Endpoint, events: ConnectionEvents) -> any ByteConnection {
        switch endpoint {
        case let .tcp(host, port):
            return TCPConnection(host: host, port: port, queue: queue, events: events)
        case let .wss(url):
            return WebSocketConnection(url: URL(string: url), session: webSocketSession, events: events)
        }
    }
}

/// Raw TCP. Reports opened once ready, every chunk read, and one close.
final class TCPConnection: ByteConnection, @unchecked Sendable {
    private let connection: NWConnection
    private let events: ConnectionEvents
    private let lock = NSLock()
    private var finished = false

    init(host: String, port: UInt16, queue: DispatchQueue, events: ConnectionEvents) {
        self.events = events
        connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .https,
            using: .tcp
        )
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.events.opened()
                self.receive()
            case let .failed(error):
                self.finish(failure: error.localizedDescription)
            case let .waiting(error):
                // No route now: fail fast so the engine's fallback moves on.
                self.finish(failure: error.localizedDescription)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.events.received(data) }
            if let error { return self.finish(failure: error.localizedDescription) }
            if isComplete { return self.finish(failure: nil) }
            self.receive()
        }
    }

    func write(_ data: Data) {
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            if let error { self?.finish(failure: error.localizedDescription) }
        })
    }

    func close() {
        lock.withLock { finished = true }
        connection.cancel()
    }

    /// The first end wins, and an end the shell asked for is not reported.
    private func finish(failure: String?) {
        let report = lock.withLock { () -> Bool in
            defer { finished = true }
            return !finished
        }
        connection.cancel()
        if report { events.closed(failure) }
    }
}

/// MQTT over a WebSocket ("mqtt" subprotocol), on the app's pinned session.
final class WebSocketConnection: ByteConnection, @unchecked Sendable {
    private let task: URLSessionWebSocketTask?
    private let events: ConnectionEvents
    private let lock = NSLock()
    private var finished = false

    init(url: URL?, session: URLSession, events: ConnectionEvents) {
        self.events = events
        guard let url else {
            task = nil
            events.closed("not a URL")
            return
        }
        let task = session.webSocketTask(with: url, protocols: ["mqtt"])
        self.task = task
        task.resume()
        // URLSession queues sends until the handshake completes, and a failed
        // handshake fails the first receive: the engine can write at once.
        events.opened()
        receive()
    }

    private func receive() {
        task?.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case let .success(.data(data)):
                self.events.received(data)
                self.receive()
            case .success:
                // MQTT over WebSocket is binary only.
                self.finish(failure: "a text frame")
            case let .failure(error):
                self.finish(failure: error.localizedDescription)
            }
        }
    }

    func write(_ data: Data) {
        task?.send(.data(data)) { [weak self] error in
            if let error { self?.finish(failure: error.localizedDescription) }
        }
    }

    func close() {
        lock.withLock { finished = true }
        task?.cancel(with: .normalClosure, reason: nil)
    }

    private func finish(failure: String?) {
        let report = lock.withLock { () -> Bool in
            defer { finished = true }
            return !finished
        }
        task?.cancel(with: .goingAway, reason: nil)
        if report { events.closed(failure) }
    }
}
