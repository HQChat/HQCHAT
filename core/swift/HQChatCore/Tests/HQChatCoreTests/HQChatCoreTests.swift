// The core through its Swift bindings, driven as the app's shell drives it:
// a KeyVault on CryptoKit's P-256 (the Secure Enclave vault has the same
// shape) and a Store over a dictionary. `swift test` in core/swift/HQChatCore,
// after core/hqchat-ffi/build-apple.sh.

import CryptoKit
import Foundation
import HQChatCore
import XCTest

final class SoftwareVault: KeyVault, @unchecked Sendable {
    private let lock = NSLock()
    private var key: P256.KeyAgreement.PrivateKey?
    private var isLocked = false

    var locked: Bool {
        get { lock.withLock { isLocked } }
        set { lock.withLock { isLocked = newValue } }
    }

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
        if locked { throw VaultError.Locked }
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
        let shared = try key.sharedSecretFromKeyAgreement(with: peer)
        return shared.withUnsafeBytes { Data($0) }
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
    var count: Int { lock.withLock { blobs.count } }
}

final class HQChatCoreTests: XCTestCase {
    private let config = Config(serverUrl: "https://hqchat.test", profileId: "p1", device: .ios)
    private let peerA = String(repeating: "a", count: 64)

    func testTheApiVersionMatchesTheBindings() {
        XCTAssertEqual(coreApiVersion(), 1)
    }

    func testAnIdentityIsCreatedSealedAndSignInStarts() throws {
        let store = DictionaryStore()
        let engine = try Engine(config: config, vault: SoftwareVault(), store: store)
        XCTAssertEqual(try engine.createIdentity(), [.tierChanged(tier: .software)])
        XCTAssertEqual(store.count, 1, "the identity is stored, sealed")

        let started = engine.start(now: 0, network: NetworkInfo(key: "wifi", expensive: false))
        let posts = started.compactMap { effect -> String? in
            guard case let .http(_, method, path, _, body) = effect, method == .post else { return nil }
            return path + " " + String(decoding: body, as: UTF8.self).prefix(7)
        }
        XCTAssertEqual(posts.first, "/auth/init {\"pk\":\"")
    }

    func testTheUnlockGoesThroughTheVaultAndLockingClosesTheState() throws {
        let vault = SoftwareVault()
        let store = DictionaryStore()
        _ = try Engine(config: config, vault: vault, store: store).createIdentity()

        let restarted = try Engine(config: config, vault: vault, store: store)
        vault.locked = true
        XCTAssertThrowsError(try restarted.unlock(now: 0)) { error in
            guard case CoreError.Locked = error else { return XCTFail("expected Locked, got \(error)") }
        }
        vault.locked = false
        XCTAssertEqual(try restarted.unlock(now: 0), [.friendsChanged])
        XCTAssertEqual(try restarted.history(peer: peerA, before: nil, limit: 5), [])
        XCTAssertThrowsError(try restarted.sendText(peer: String(repeating: "b", count: 64), text: "hi", now: 0)) { error in
            guard case CoreError.NotAFriend = error else { return XCTFail("expected NotAFriend, got \(error)") }
        }
        _ = restarted.lock()
        XCTAssertNil(try? restarted.history(peer: peerA, before: nil, limit: 5), "locked again")
    }
}
