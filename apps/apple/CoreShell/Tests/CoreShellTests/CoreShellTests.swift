// The shell around the real engine, with a software vault, a dictionary
// store, and fake HTTP and connections: what the shell does with each effect.

import CoreShell
import CryptoKit
import Foundation
import HQChatCore
import XCTest

final class SoftwareVault: KeyVault, @unchecked Sendable {
    private let lock = NSLock()
    private var key: P256.KeyAgreement.PrivateKey?

    func create() throws -> Tier {
        lock.withLock { if key == nil { key = P256.KeyAgreement.PrivateKey() } }
        return .software
    }

    func devicePublicKey() throws -> Data {
        guard let key = lock.withLock({ key }) else { throw VaultError.Missing }
        return key.publicKey.x963Representation
    }

    func agree(ephemeralPublic: Data) throws -> Data {
        guard let key = lock.withLock({ key }) else { throw VaultError.Missing }
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
        return try key.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
    }

    func tier() -> Tier { .software }
}

final class DictionaryStore: Store, @unchecked Sendable {
    private var blobs: [String: Data] = [:]
    private let lock = NSLock()
    func get(key: String) -> Data? { lock.withLock { blobs[key] } }
    func put(key: String, value: Data) throws { lock.withLock { blobs[key] = value } }
    func delete(key: String) { lock.withLock { _ = blobs.removeValue(forKey: key) } }
    func list(prefix: String) -> [String] { lock.withLock { blobs.keys.filter { $0.hasPrefix(prefix) }.sorted() } }
}

/// Records every request and answers each with `status` (0: unreachable).
final class FakeHTTP: HTTPPerformer, @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [(method: String, url: URL, bearer: String?)] = []
    let status: UInt16

    init(status: UInt16 = 0) { self.status = status }

    var requests: [(method: String, url: URL, bearer: String?)] { lock.withLock { seen } }

    func perform(method: HQChatCore.Method, url: URL, bearer: String?, body: Data) async -> (status: UInt16, body: Data) {
        lock.withLock { seen.append((method == .get ? "GET" : "POST", url, bearer)) }
        return (status, Data())
    }
}

struct NoConnections: ConnectionFactory {
    struct Never: ByteConnection {
        func write(_ data: Data) {}
        func close() {}
    }

    func open(_ endpoint: Endpoint, events: ConnectionEvents) -> any ByteConnection {
        Never()
    }
}

final class Prompts: @unchecked Sendable {
    private let lock = NSLock()
    private var reasons: [UnlockReason] = []
    let answer: Bool
    init(answer: Bool) { self.answer = answer }
    func ask(_ reason: UnlockReason) -> Bool {
        lock.withLock { reasons.append(reason) }
        return answer
    }
    var asked: [UnlockReason] { lock.withLock { reasons } }
}

final class CoreShellTests: XCTestCase {
    private let config = Config(serverUrl: "https://hqchat.test", profileId: "p", device: .ios)
    private let network = NetworkInfo(key: "wifi", expensive: false)
    private let base = URL(string: "https://hqchat.test")!

    private func eventually(_ what: String, _ done: () -> Bool) async throws {
        for _ in 0..<200 where !done() {
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertTrue(done(), "timed out waiting for \(what)")
    }

    private func shell(_ engine: Engine, http: FakeHTTP, prompts: Prompts) -> CoreShell {
        CoreShell(
            engine: engine, baseURL: base, http: http, connections: NoConnections(),
            askToUnlock: { prompts.ask($0) }, onEffect: { _ in }
        )
    }

    func testSignInGoesToTheHomeServerWithoutABearer() async throws {
        let engine = try Engine(config: config, vault: SoftwareVault(), store: DictionaryStore())
        _ = try engine.createIdentity()
        let http = FakeHTTP()
        await shell(engine, http: http, prompts: Prompts(answer: true)).start(network: network)
        try await eventually("the sign-in request") { !http.requests.isEmpty }
        XCTAssertEqual(http.requests.first?.method, "POST")
        XCTAssertEqual(http.requests.first?.url.absoluteString, "https://hqchat.test/auth/init")
        XCTAssertNil(http.requests.first?.bearer)
    }

    func testALockedProfileAsksForTheUnlockThenSignsIn() async throws {
        let vault = SoftwareVault()
        let store = DictionaryStore()
        _ = try Engine(config: config, vault: vault, store: store).createIdentity()
        let restarted = try Engine(config: config, vault: vault, store: store)

        let prompts = Prompts(answer: true)
        let http = FakeHTTP()
        await shell(restarted, http: http, prompts: prompts).start(network: network)
        try await eventually("the sign-in after the unlock") { !http.requests.isEmpty }
        XCTAssertEqual(prompts.asked, [.signIn])
        XCTAssertEqual(http.requests.first?.url.path, "/auth/init")
    }

    func testARefusedPromptSendsNothing() async throws {
        let vault = SoftwareVault()
        let store = DictionaryStore()
        _ = try Engine(config: config, vault: vault, store: store).createIdentity()
        let restarted = try Engine(config: config, vault: vault, store: store)

        let prompts = Prompts(answer: false)
        let http = FakeHTTP()
        await shell(restarted, http: http, prompts: prompts).start(network: network)
        try await eventually("the prompt") { !prompts.asked.isEmpty }
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertTrue(http.requests.isEmpty, "nothing leaves before the user unlocks")
    }
}
