import Foundation

/// MQTT 3.1.1, hand-rolled so it runs over the app's own transports (WSS with
/// the same SPKI pinning as REST, or hqn/1) without a third-party WebSocket and
/// TLS stack. Implements CONNECT/CONNACK (persistent session, Last-Will,
/// username/password), PUBLISH/PUBACK at QoS 0/1, SUBSCRIBE/SUBACK,
/// UNSUBSCRIBE/UNSUBACK, PINGREQ/PINGRESP and DISCONNECT. The persistent session
/// is the offline queue: the broker holds QoS-1 messages while disconnected.

// MARK: - Packet coding (pure; unit-testable without a socket)

enum MQTTPacketType: UInt8 {
    case connect = 1, connack = 2, publish = 3, puback = 4
    case subscribe = 8, suback = 9, unsubscribe = 10, unsuback = 11
    case pingreq = 12, pingresp = 13, disconnect = 14
}

/// One decoded packet: the fixed-header byte (type + flags) and the variable
/// header + payload that follow it.
struct MQTTPacket: Equatable {
    let header: UInt8
    let body: Data

    var type: MQTTPacketType? { MQTTPacketType(rawValue: header >> 4) }
    var flags: UInt8 { header & 0x0F }
}

enum MQTTCodec {

    // --- primitives ---------------------------------------------------------

    /// MQTT "remaining length": 7 bits per byte, high bit = continuation.
    static func encodeLength(_ length: Int) -> Data {
        var out = Data()
        var value = length
        repeat {
            var byte = UInt8(value % 128)
            value /= 128
            if value > 0 { byte |= 0x80 }
            out.append(byte)
        } while value > 0
        return out
    }

    /// The largest packet accepted before failing the connection, so a hostile
    /// length prefix cannot grow the buffer toward 256 MB. The largest legitimate
    /// frame (an `init`) is ~82 kB.
    static let maxPacketBytes = 256 * 1024

    /// Packets above this size are logged, not refused.
    static let packetWarningBytes = 128 * 1024

    /// What a remaining-length prefix turned out to be.
    enum LengthPrefix: Equatable {
        case complete(value: Int, bytes: Int)
        /// More bytes needed before the prefix can be read at all.
        case incomplete
        /// Not a length prefix, and never will be. Drop the connection.
        case malformed
    }

    static func decodeLength(_ data: Data, from offset: Int) -> LengthPrefix {
        var multiplier = 1
        var value = 0
        var index = offset
        var consumed = 0
        while index < data.count {
            let byte = data[data.startIndex + index]
            value += Int(byte & 0x7F) * multiplier
            consumed += 1
            if byte & 0x80 == 0 { return .complete(value: value, bytes: consumed) }
            // MQTT 3.1.1 caps the length encoding at four bytes.
            if consumed == 4 { return .malformed }
            multiplier *= 128
            index += 1
        }
        return .incomplete
    }

    /// Length-prefixed UTF-8, the only string form MQTT 3.1.1 has.
    static func encodeString(_ s: String) -> Data {
        let bytes = Data(s.utf8)
        var out = Data([UInt8(bytes.count >> 8), UInt8(bytes.count & 0xFF)])
        out.append(bytes)
        return out
    }

    static func encodeData(_ d: Data) -> Data {
        var out = Data([UInt8(d.count >> 8), UInt8(d.count & 0xFF)])
        out.append(d)
        return out
    }

    static func packet(_ type: MQTTPacketType, flags: UInt8 = 0, body: Data) -> Data {
        var out = Data([(type.rawValue << 4) | flags])
        out.append(encodeLength(body.count))
        out.append(body)
        return out
    }

    // --- outbound packets ---------------------------------------------------

    static func connect(clientID: String, username: String, password: String,
                        willTopic: String?, willPayload: Data?, willRetain: Bool,
                        keepAlive: UInt16, cleanSession: Bool) -> Data {
        var body = encodeString("MQTT")
        body.append(0x04)                                   // protocol level 3.1.1

        var flags: UInt8 = 0
        if !username.isEmpty { flags |= 0x80 }
        if !password.isEmpty { flags |= 0x40 }
        if willTopic != nil {
            flags |= 0x04                                   // will flag
            flags |= (1 << 3)                               // will QoS 1
            if willRetain { flags |= 0x20 }
        }
        if cleanSession { flags |= 0x02 }
        body.append(flags)
        body.append(contentsOf: [UInt8(keepAlive >> 8), UInt8(keepAlive & 0xFF)])

        body.append(encodeString(clientID))
        if let willTopic, let willPayload {
            body.append(encodeString(willTopic))
            body.append(encodeData(willPayload))
        }
        if !username.isEmpty { body.append(encodeString(username)) }
        if !password.isEmpty { body.append(encodeString(password)) }
        return packet(.connect, body: body)
    }

    static func publish(topic: String, payload: Data, qos: Int, retained: Bool,
                        packetID: UInt16?, dup: Bool = false) -> Data {
        var flags: UInt8 = UInt8((qos & 0x03) << 1)
        if retained { flags |= 0x01 }
        if dup { flags |= 0x08 }
        var body = encodeString(topic)
        if qos > 0, let packetID {
            body.append(contentsOf: [UInt8(packetID >> 8), UInt8(packetID & 0xFF)])
        }
        body.append(payload)
        return packet(.publish, flags: flags, body: body)
    }

    static func puback(packetID: UInt16) -> Data {
        packet(.puback, body: Data([UInt8(packetID >> 8), UInt8(packetID & 0xFF)]))
    }

    static func subscribe(topic: String, qos: Int, packetID: UInt16) -> Data {
        var body = Data([UInt8(packetID >> 8), UInt8(packetID & 0xFF)])
        body.append(encodeString(topic))
        body.append(UInt8(qos & 0x03))
        return packet(.subscribe, flags: 0x02, body: body)   // reserved bits = 0010
    }

    static func unsubscribe(topic: String, packetID: UInt16) -> Data {
        var body = Data([UInt8(packetID >> 8), UInt8(packetID & 0xFF)])
        body.append(encodeString(topic))
        return packet(.unsubscribe, flags: 0x02, body: body)
    }

    static func pingreq() -> Data { packet(.pingreq, body: Data()) }
    static func disconnect() -> Data { packet(.disconnect, body: Data()) }

    /// The packet id a SUBACK answers and its per-topic return codes; a code
    /// >= 0x80 is a refusal (the topic ACL), not an error. Nil for a body too
    /// short to carry an id and one code.
    static func subackReturnCodes(_ body: Data) -> (packetID: UInt16, codes: [UInt8])? {
        guard body.count >= 3 else { return nil }
        let start = body.startIndex
        let id = UInt16(body[start]) << 8 | UInt16(body[start + 1])
        return (id, [UInt8](body[(start + 2)...]))
    }

    // --- inbound parsing ----------------------------------------------------

    /// What one call to `nextPacket` found at the head of the buffer (which may
    /// hold a partial packet, several, or both).
    enum NextPacket: Equatable {
        case packet(MQTTPacket)
        /// A whole packet is not here yet. Keep the buffer and wait.
        case incomplete
        /// Unparseable, or larger than accepted: fail the connection.
        case malformed(reason: String)
    }

    /// The packet, when there is one; for tests and fuzzing. The receive path
    /// switches over `NextPacket` so `.malformed` is never mistaken for "wait".
    static func packetIfAny(from buffer: inout Data) -> MQTTPacket? {
        if case .packet(let p) = nextPacket(from: &buffer) { return p }
        return nil
    }

    static func nextPacket(from buffer: inout Data) -> NextPacket {
        guard buffer.count >= 2 else { return .incomplete }
        let prefix = decodeLength(buffer, from: 1)
        guard case .complete(let remaining, let lengthBytes) = prefix else {
            return prefix == .malformed
                ? .malformed(reason: "remaining-length ran past four continuation bytes")
                : .incomplete
        }
        let total = 1 + lengthBytes + remaining
        // Checked against the claimed length before buffering any of it.
        guard total <= maxPacketBytes else {
            return .malformed(reason: "packet claims \(total) bytes, over the \(maxPacketBytes) limit")
        }
        guard buffer.count >= total else { return .incomplete }

        let header = buffer[buffer.startIndex]
        let bodyStart = buffer.startIndex + 1 + lengthBytes
        let body = Data(buffer[bodyStart..<(buffer.startIndex + total)])
        buffer.removeFirst(total)
        return .packet(MQTTPacket(header: header, body: body))
    }

    /// Decodes a PUBLISH body into topic / packet id (QoS > 0) / payload.
    static func parsePublish(_ p: MQTTPacket) -> (topic: String, packetID: UInt16?, payload: Data)? {
        let body = p.body
        guard body.count >= 2 else { return nil }
        let base = body.startIndex
        let topicLen = Int(body[base]) << 8 | Int(body[base + 1])
        guard body.count >= 2 + topicLen else { return nil }
        guard let topic = String(data: body[(base + 2)..<(base + 2 + topicLen)], encoding: .utf8) else { return nil }

        var cursor = base + 2 + topicLen
        var packetID: UInt16?
        let qos = (p.flags >> 1) & 0x03
        if qos > 0 {
            guard body.count >= (cursor - base) + 2 else { return nil }
            packetID = UInt16(body[cursor]) << 8 | UInt16(body[cursor + 1])
            cursor += 2
        }
        return (topic, packetID, Data(body[cursor...]))
    }

    /// CONNACK return code (0 = accepted).
    static func connackCode(_ p: MQTTPacket) -> UInt8? {
        guard p.body.count >= 2 else { return nil }
        return p.body[p.body.startIndex + 1]
    }

    /// PUBACK's two-byte packet id.
    static func pubackPacketID(_ body: Data) -> UInt16? {
        guard body.count >= 2 else { return nil }
        return UInt16(body[body.startIndex]) << 8 | UInt16(body[body.startIndex + 1])
    }
}

/// What to do with QoS-1 publishes still unacknowledged when a session comes
/// up. MQTT 3.1.1 has no negative acknowledgement, so a publish the broker
/// refuses would be replayed forever; after `maxReplays` it is abandoned.
enum ReplayPolicy {

    /// Attempts allowed before a packet is abandoned.
    static let maxReplays = 3

    /// Split in-flight publishes, by how many times each has already been sent,
    /// into those to re-send now and those to give up on.
    static func plan(attempts: [UInt16: Int]) -> (replay: [UInt16], abandon: [UInt16]) {
        var replay: [UInt16] = []
        var abandon: [UInt16] = []
        for (id, n) in attempts {
            if n >= maxReplays { abandon.append(id) } else { replay.append(id) }
        }
        return (replay.sorted(), abandon.sorted())
    }
}

/// Whether a connected link still carries anything: each PINGREQ opens a
/// deadline that any inbound bytes close. A silently dead path (lost Wi-Fi,
/// dropped NAT mapping) is otherwise noticed only after minutes.
struct PingLiveness {

    /// How long to wait for any inbound bytes after a PINGREQ.
    static let pongTimeout: TimeInterval = 10

    private(set) var pingSentAt: TimeInterval?
    private(set) var lastInboundAt: TimeInterval?

    /// A PINGREQ went out; an outstanding ping keeps its original deadline.
    mutating func pingSent(at now: TimeInterval) {
        if pingSentAt == nil { pingSentAt = now }
    }

    /// Bytes arrived. Whatever they were, the path is alive.
    mutating func inbound(at now: TimeInterval) {
        lastInboundAt = now
        pingSentAt = nil
    }

    /// True once a ping has gone unanswered for `pongTimeout`.
    func isOverdue(at now: TimeInterval) -> Bool {
        guard let sent = pingSentAt else { return false }
        return now - sent >= Self.pongTimeout
    }
}

// MARK: - Transport

/// The MQTT 3.1.1 session — codec, CONNACK, replay, keepalive — over whichever
/// byte pipe the endpoint URL names (MQTTTransport.swift): `wss://` through
/// nginx with SPKI pinning, or `hqn://` over raw TCP inside hqn/1.
final class MQTTWireClient: MQTTBackend, @unchecked Sendable {

    enum MQTTError: LocalizedError {
        case connectionRefused(UInt8)
        case notConnected
        /// The byte stream cannot be parsed as MQTT, or claims a packet larger
        /// than `MQTTCodec.maxPacketBytes`. Terminal for the connection: there is
        /// no resynchronisation point in a length-prefixed stream once the length
        /// is untrustworthy, and continuing to buffer is the failure this
        /// replaced.
        case malformedStream(String)
        /// A PINGREQ went unanswered for `PingLiveness.pongTimeout`, with no
        /// other traffic either: the path is dead even though the socket says
        /// otherwise.
        case keepaliveTimeout
        /// The caller abandoned the link because the device's network path
        /// changed underneath it (see `abandonLink`).
        case linkAbandoned

        var errorDescription: String? {
            switch self {
            case .connectionRefused(let code):
                // 4 = bad username or password, 5 = not authorised (a stale or replayed proof).
                return "MQTT connection refused by the broker (code \(code))"
            case .notConnected:
                return "MQTT is not connected"
            case .malformedStream(let reason):
                return "MQTT stream is unparseable: \(reason)"
            case .keepaliveTimeout:
                return "MQTT broker stopped answering keepalive pings"
            case .linkAbandoned:
                return "MQTT link abandoned after a network path change"
            }
        }
    }

    /// MQTT keepalive in seconds; pings go out at half, and the broker drops a
    /// silent client after 1.5x.
    private let keepAlive: UInt16 = 60

    private let queue = DispatchQueue(label: "mqtt.wire")
    /// Builds the byte pipe for an endpoint. Injectable so the session logic
    /// can be driven through a fake transport in tests.
    private let makeTransport: (URL) -> ByteTransport
    private var link: ByteTransport?

    init(makeTransport: @escaping (URL) -> ByteTransport = MQTTTransports.make(for:)) {
        self.makeTransport = makeTransport
    }
    private var pingTimer: DispatchSourceTimer?
    private var liveness = PingLiveness()
    /// Bumped per connection, so a pong deadline armed for a previous link
    /// cannot fail the current one.
    private var linkGeneration = 0

    private var buffer = Data()
    private var onEvent: ((MQTTEvent) -> Void)?
    private var connected = false          // CONNACK received
    private var closed = false             // terminal for this connection
    private var nextID: UInt16 = 1

    /// QoS-1 publishes awaiting PUBACK, re-sent (with DUP) after a reconnect so a
    /// message composed during a blip is not silently lost.
    private var unacked: [UInt16: (topic: String, payload: Data, retained: Bool, attempts: Int)] = [:]

    /// Packets handed over before CONNACK, flushed in order once the session is up.
    private var pending: [Data] = []

    /// The client id the queues above belong to; see `adoptIdentity`.
    private var sessionIdentity: String?

    /// Topic per in-flight SUBSCRIBE packet id, so a SUBACK refusal can name its topic.
    private var subscribeTopics: [UInt16: String] = [:]

    // MARK: MQTTBackend

    func connect(url: URL, clientID: String, username: String, password: String,
                 willTopic: String, willPayload: Data,
                 onEvent: @escaping (MQTTEvent) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            self.teardown(notify: false)
            self.adoptIdentity(clientID)
            self.onEvent = onEvent
            self.closed = false
            self.connected = false
            self.buffer.removeAll()
            self.liveness = PingLiveness()
            self.linkGeneration &+= 1

            // The CONNECT opens the transport: hqn/1 carries it in its first handshake message.
            let generation = self.linkGeneration
            let link = self.makeTransport(url)
            self.link = link
            link.start(
                opening: MQTTCodec.connect(
                    clientID: clientID, username: username, password: password,
                    willTopic: willTopic, willPayload: willPayload, willRetain: true,
                    keepAlive: self.keepAlive, cleanSession: false),
                onReceive: { [weak self] data in
                    self?.queue.async {
                        guard let self, self.linkGeneration == generation, !self.closed else { return }
                        self.ingest(data)
                    }
                },
                onClose: { [weak self] error in
                    self?.queue.async {
                        guard let self, self.linkGeneration == generation else { return }
                        self.fail(error ?? MQTTError.notConnected)
                    }
                })
        }
    }

    func subscribe(_ topic: String, qos: Int) {
        queue.async {
            let id = self.takeID()
            self.subscribeTopics[id] = topic
            self.enqueue(MQTTCodec.subscribe(topic: topic, qos: qos, packetID: id))
        }
    }

    func unsubscribe(_ topic: String) {
        queue.async {
            let id = self.takeID()
            self.enqueue(MQTTCodec.unsubscribe(topic: topic, packetID: id))
        }
    }

    /// Publishes a frame. `onWrite`, when given, reports whether it reached the
    /// socket (false when buffered for the next CONNACK), for callers that hold a
    /// background assertion until the bytes have left.
    func publish(_ topic: String, payload: Data, qos: Int, retained: Bool,
                 onWrite: ((Bool) -> Void)? = nil) {
        queue.async {
            if qos > 0 {
                let id = self.takeID()
                self.unacked[id] = (topic, payload, retained, 0)
                self.enqueue(MQTTCodec.publish(topic: topic, payload: payload, qos: qos,
                                               retained: retained, packetID: id),
                             replayedFromUnacked: true, then: onWrite)
            } else {
                self.enqueue(MQTTCodec.publish(topic: topic, payload: payload, qos: 0,
                                               retained: retained, packetID: nil),
                             then: onWrite)
            }
        }
    }

    func disconnect() {
        queue.async {
            if self.connected { self.send(MQTTCodec.disconnect()) }
            self.teardown(notify: false)
        }
    }

    /// Drops a link presumed dead (the network path changed) and reports it, so
    /// the reconnect loop runs. No DISCONNECT is sent, so the broker publishes
    /// the Last-Will.
    func abandonLink() {
        queue.async {
            guard !self.closed else { return }
            self.fail(MQTTError.linkAbandoned)
        }
    }

    /// In-flight QoS-1 publishes, for diagnostics and tests.
    var inFlightPublishCount: Int { queue.sync { unacked.count } }

    // MARK: Internals (all on `queue`)

    /// Takes `clientID` as this connection's identity, dropping anything queued
    /// for a different one: after a profile switch, replaying the previous
    /// identity's publishes would send frames under the wrong sender.
    func adoptIdentity(_ clientID: String) {
        if clientID != sessionIdentity {
            unacked.removeAll()
            pending.removeAll()
        }
        sessionIdentity = clientID
    }

    private func takeID() -> UInt16 {
        let id = nextID
        nextID = nextID == UInt16.max ? 1 : nextID + 1
        return id
    }

    /// Sends now if the session is up, otherwise holds until CONNACK; `then`
    /// reports whether the packet reached the socket.
    private func enqueue(_ packet: Data, replayedFromUnacked: Bool = false,
                         then: ((Bool) -> Void)? = nil) {
        if connected {
            send(packet, then: then)
            return
        }
        // QoS-1 publishes are replayed from `unacked`; `pending` holds only QoS-0
        // publishes and control packets.
        if !replayedFromUnacked { pending.append(packet) }
        then?(false)
    }

    private func send(_ packet: Data, then: ((Bool) -> Void)? = nil) {
        guard let link else { then?(false); return }
        link.send(packet) { error in then?(error == nil) }
    }

    private func ingest(_ data: Data) {
        liveness.inbound(at: Self.now())
        buffer.append(data)
        loop: while true {
            switch MQTTCodec.nextPacket(from: &buffer) {
            case .packet(let packet):
                handle(packet)
            case .incomplete:
                break loop
            case .malformed(let reason):
                // The stream cannot be resynchronised, so the connection goes.
                fail(MQTTError.malformedStream(reason))
                return
            }
        }
    }

    private func handle(_ packet: MQTTPacket) {
        switch packet.type {
        case .connack:
            guard let code = MQTTCodec.connackCode(packet) else { return }
            guard code == 0 else { fail(MQTTError.connectionRefused(code)); return }
            connected = true
            startPing()
            // Replay what was in flight (bounded by `ReplayPolicy`), then drain what
            // was queued while connecting.
            let plan = ReplayPolicy.plan(attempts: unacked.mapValues { $0.attempts })
            for id in plan.abandon {
                guard let p = unacked.removeValue(forKey: id) else { continue }
                onEvent?(.publishAbandoned(topic: p.topic, attempts: p.attempts))
            }
            for id in plan.replay {
                guard let p = unacked[id] else { continue }
                unacked[id]?.attempts = p.attempts + 1
                onEvent?(.publishReplayed(topic: p.topic, attempt: p.attempts + 1))
                send(MQTTCodec.publish(topic: p.topic, payload: p.payload, qos: 1,
                                       retained: p.retained, packetID: id, dup: true))
            }
            let queued = pending
            pending.removeAll()
            for packet in queued { send(packet) }
            onEvent?(.connected)

        case .publish:
            guard let (topic, packetID, payload) = MQTTCodec.parsePublish(packet) else { return }
            // QoS 1 inbound: acknowledge so EMQX stops redelivering.
            if let packetID, (packet.flags >> 1) & 0x03 == 1 {
                send(MQTTCodec.puback(packetID: packetID))
            }
            onEvent?(.message(topic: topic, payload: payload))

        case .puback:
            guard let id = MQTTCodec.pubackPacketID(packet.body) else { return }
            unacked.removeValue(forKey: id)

        case .suback:
            // A refused subscription arrives as SUBACK return code 0x80, not as an error.
            guard let ack = MQTTCodec.subackReturnCodes(packet.body) else { return }
            let topic = subscribeTopics.removeValue(forKey: ack.packetID)
            for code in ack.codes where code >= 0x80 {
                onEvent?(.subscribeRefused(topic: topic ?? "(unknown topic)", code: code))
            }

        case .unsuback, .pingresp:
            break   // nothing to do

        default:
            break
        }
    }

    private func startPing() {
        pingTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        let interval = Double(keepAlive) / 2
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in
            guard let self, self.connected else { return }
            self.send(MQTTCodec.pingreq())
            self.liveness.pingSent(at: Self.now())
            self.armPongDeadline()
        }
        timer.resume()
        pingTimer = timer
    }

    /// Checks, once `pongTimeout` has passed, whether anything came back since
    /// the ping. Only the link that armed it may be failed by it.
    private func armPongDeadline() {
        let generation = linkGeneration
        queue.asyncAfter(deadline: .now() + PingLiveness.pongTimeout) { [weak self] in
            guard let self, self.linkGeneration == generation,
                  self.connected, !self.closed else { return }
            if self.liveness.isOverdue(at: Self.now()) {
                self.fail(MQTTError.keepaliveTimeout)
            }
        }
    }

    private static func now() -> TimeInterval { ProcessInfo.processInfo.systemUptime }

    /// Terminal failure: reports once and tears down. MQTTService owns reconnecting.
    private func fail(_ error: Error) {
        guard !closed else { return }
        let handler = onEvent
        teardown(notify: false)
        handler?(.disconnected(error))
    }

    private func teardown(notify: Bool) {
        closed = true
        connected = false
        pingTimer?.cancel()
        pingTimer = nil
        link?.cancel()
        link = nil
        pending.removeAll()
        subscribeTopics.removeAll()
        if notify { onEvent?(.disconnected(nil)) }
    }
}
