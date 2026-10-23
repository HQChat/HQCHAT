import CoreShell
import CryptoKit
import Foundation
import HQChatCore

// The app's own ChatStore (the core, its shell, the store the screens read),
// live against the local e2e stack: two users sign up, connect over hqn/1
// through noise-gw, befriend each other, exchange messages and read them;
// a third, whose raw TCP is refused, falls back to WSS and messages them. Only
// the vault is a software one: the Secure Enclave needs a signed device build.
//
// Driven by run.sh, which is driven by services/server/test/scenarios/run-local.sh.
// Environment: TEST_BASE_URL, TEST_MQTT_URL, TEST_HQN_HOST (optional).

var failures = 0
func check(_ ok: Bool, _ label: String) {
    print(ok ? "  ✓ \(label)" : "  ✗ \(label)")
    if !ok { failures += 1 }
}

let env = ProcessInfo.processInfo.environment
let base = URL(string: env["TEST_BASE_URL"] ?? "http://127.0.0.1:8090")!
let mqtt = env["TEST_MQTT_URL"] ?? "ws://127.0.0.1:8083/mqtt"
let hqnHost = env["TEST_HQN_HOST"]

/// A P-256 key in memory, standing in for the Enclave.
final class SoftwareVault: KeyVault, @unchecked Sendable {
    private let key = P256.KeyAgreement.PrivateKey()
    func create() throws -> Tier { .software }
    func devicePublicKey() throws -> Data { key.publicKey.x963Representation }
    func agree(ephemeralPublic: Data) throws -> Data {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
        return try key.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
    }
    func stateSecret() throws -> Data { Data(SHA256.hash(data: key.rawRepresentation)) }
    func tier() -> Tier { .software }
}

/// The platform's connections, with the stack's addresses: the gateway as the
/// harness reaches it, and the broker's WebSocket port. `refuseTCP` makes
/// every hqn/1 attempt fail, so the engine falls back to WSS.
/// Which transports a user's engine opened.
final class Opened: @unchecked Sendable {
    private let lock = NSLock()
    private var tcp = 0, wss = 0
    func count(tcp isTCP: Bool) { lock.withLock { if isTCP { tcp += 1 } else { wss += 1 } } }
    var counts: (tcp: Int, wss: Int) { lock.withLock { (tcp, wss) } }
}

struct StackConnections: ConnectionFactory {
    let platform: PlatformConnections
    let refuseTCP: Bool
    let opened: Opened

    func open(_ endpoint: Endpoint, events: ConnectionEvents) -> any ByteConnection {
        if case .tcp = endpoint { opened.count(tcp: true) } else { opened.count(tcp: false) }
        switch endpoint {
        case let .tcp(host, port):
            if refuseTCP { return platform.open(.tcp(host: "127.0.0.1", port: 1), events: events) }
            return platform.open(.tcp(host: hqnHost ?? host, port: port), events: events)
        case .wss:
            return platform.open(.wss(url: mqtt), events: events)
        }
    }
}

var transports: [String: Opened] = [:]

@MainActor
func user(_ name: String, refuseTCP: Bool = false) async throws -> ChatStore {
    let opened = Opened()
    transports[name] = opened
    let store = try ChatStore(profileID: UUID(), username: name, server: base, vault: SoftwareVault()) { session in
        StackConnections(platform: PlatformConnections(webSocketSession: session), refuseTCP: refuseTCP,
                         opened: opened)
    }
    try await store.createIdentity()
    store.start()
    return store
}

@MainActor
func until(_ seconds: Double = 20, _ condition: () -> Bool) async -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        if condition() { return true }
        try? await Task.sleep(nanoseconds: 100_000_000)
    }
    return condition()
}

@MainActor
func run() async throws {
    ChatStore.rootOverride = FileManager.default.temporaryDirectory
        .appendingPathComponent("hqchat-live-\(UUID().uuidString)", isDirectory: true)
    let tag = String(UUID().uuidString.prefix(6)).lowercased()
    let (aliceName, bobName, carolName) = ("swift_a\(tag)", "swift_b\(tag)", "swift_c\(tag)")

    print("")
    print("hqn/1 through noise-gw")
    let alice = try await user(aliceName)
    let bob = try await user(bobName)
    check(await until { alice.connection == .connected && bob.connection == .connected },
          "both stores sign in and connect")
    check(transports[aliceName]!.counts == (1, 0) && transports[bobName]!.counts == (1, 0),
          "over hqn/1, never touching WSS")
    try await alice.setUsername(aliceName)
    try await bob.setUsername(bobName)
    check(true, "usernames claimed")

    try await alice.invite(bobName)
    check(alice.contacts.contains { $0.inviteStatus == .inviteSent && $0.username == bobName },
          "a sent request is listed")
    check(await until { bob.contacts.contains { $0.inviteStatus == .inviteReceived } },
          "the request reaches bob")
    let request = bob.contacts.first { $0.inviteStatus == .inviteReceived }!
    try await bob.accept(request)
    check(await until { alice.contacts.contains { $0.username == bobName && $0.inviteStatus == .accepted && $0.hasPinnedKey } },
          "alice has bob as a friend, his key pinned")
    let bobID = alice.contacts.first { $0.username == bobName }!.peerID
    let aliceID = bob.contacts.first { $0.username == aliceName }!.peerID

    // Accepting greets on the user's behalf; then a message each way.
    check(await until { alice.contacts.first { $0.peerID == bobID }?.lastMessage != nil },
          "bob's greeting arrives")
    try await alice.send("hello from swift", to: bobID)
    check(await until { bob.contacts.first { $0.peerID == aliceID }?.lastMessage?.content == "hello from swift" },
          "alice's message reaches bob")
    check(await until { (bob.contacts.first { $0.peerID == aliceID }?.unread ?? 0) >= 1 }, "it counts as unread")
    bob.loadConversation(aliceID)
    bob.markRead(aliceID)
    check(await until { bob.contacts.first { $0.peerID == aliceID }?.unread == 0 }, "reading clears it")
    alice.loadConversation(bobID)
    check(await until { alice.messages(with: bobID).last?.deliveryStatus == .delivered },
          "alice sees it delivered")
    try await bob.send("and back", to: aliceID)
    check(await until { alice.messages(with: bobID).last?.content == "and back" },
          "bob's reply reaches alice's open conversation")
    check(alice.safetyNumber(with: bobID) == bob.safetyNumber(with: aliceID) && alice.safetyNumber(with: bobID) != nil,
          "both sides show the same safety number")

    print("")
    print("WSS, the fallback path")
    let carol = try await user(carolName, refuseTCP: true)
    check(await until { carol.connection == .connected }, "with hqn/1 refused, carol connects over WSS")
    check(transports[carolName]!.counts.wss >= 1, "her engine moved to WSS after the refused attempt")
    try await carol.setUsername(carolName)
    try await carol.invite(aliceName)
    check(await until { alice.contacts.contains { $0.username == carolName && $0.inviteStatus == .inviteReceived } },
          "her request reaches alice")
    try await alice.accept(alice.contacts.first { $0.username == carolName }!)
    check(await until { carol.contacts.contains { $0.username == aliceName && $0.hasPinnedKey } }, "they are friends")
    let carolID = alice.contacts.first { $0.username == carolName }!.peerID
    check(await until { carol.contacts.first { $0.username == aliceName }?.lastMessage != nil },
          "alice's greeting crosses from hqn/1 to WSS")
    try await carol.send("over websockets", to: carol.contacts.first { $0.username == aliceName }!.peerID)
    check(await until { alice.contacts.first { $0.peerID == carolID }?.lastMessage?.content == "over websockets" },
          "and carol's message crosses back")

    print("")
    print("blocking")
    try await alice.block(alice.contacts.first { $0.peerID == carolID }!)
    check(await until { alice.contacts.first { $0.peerID == carolID }?.isBlocked == true },
          "a blocked friend is kept, read-only")
    do {
        try await alice.send("nope", to: carolID)
        check(false, "nothing is sent to a blocked friend")
    } catch {
        check(true, "nothing is sent to a blocked friend")
    }

    for store in [alice, bob, carol] { await store.stop() }
    try? FileManager.default.removeItem(at: ChatStore.rootOverride!)
}

do {
    try await run()
} catch {
    print("  ✗ \(error)")
    failures += 1
}
print("")
if failures > 0 { print("✗ \(failures) live check(s) failed"); exit(1) }
print("✅ the app's store live over hqn/1 and WSS")
