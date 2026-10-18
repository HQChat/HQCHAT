// The generated Swift bindings, driven as the Apple shell will: a KeyVault
// on CryptoKit's P-256 (the Secure Enclave adapter has the same shape) and a
// Store over a dictionary. Built and run by run.sh.

import CryptoKit
import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print(ok ? "  ok   \(what)" : "  FAIL \(what)")
    if !ok { failures += 1 }
}

final class SoftwareVault: KeyVault, @unchecked Sendable {
    var key: P256.KeyAgreement.PrivateKey?
    var locked = false

    func create() throws -> Tier {
        if key == nil { key = P256.KeyAgreement.PrivateKey() }
        return .software
    }

    func devicePublicKey() throws -> Data {
        guard let key else { throw VaultError.Missing }
        return key.publicKey.x963Representation
    }

    func agree(ephemeralPublic: Data) throws -> Data {
        guard let key else { throw VaultError.Missing }
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

print("HQChat core through the Swift bindings\n")
let config = Config(serverUrl: "https://hqchat.test", profileId: "p1", device: .ios)
let vault = SoftwareVault()
let store = DictionaryStore()

do {
    check(coreApiVersion() == 1, "the API version matches the bindings")
    let engine = try Engine(config: config, vault: vault, store: store)
    let created = try engine.createIdentity()
    check(created == [.tierChanged(tier: .software)], "createIdentity reports the vault's tier")
    check(store.count == 1, "the identity is stored, sealed")

    let started = engine.start(now: 0, network: NetworkInfo(key: "wifi", expensive: false))
    let signIn = started.compactMap { effect -> String? in
        if case let .http(_, method, path, _, body) = effect, method == .post { return path + " " + String(decoding: body, as: UTF8.self).prefix(7) }
        return nil
    }
    check(signIn.first == "/auth/init {\"pk\":\"", "start asks the shell to POST /auth/init")

    let restarted = try Engine(config: config, vault: vault, store: store)
    vault.locked = true
    do {
        _ = try restarted.unlock(now: 0)
        check(false, "a locked vault refuses the unlock")
    } catch CoreError.Locked {
        check(true, "a locked vault surfaces as CoreError.Locked")
    }
    vault.locked = false
    check(try restarted.unlock(now: 0) == [.friendsChanged], "the unlock opens the state through the Swift vault")
    check(try restarted.history(peer: String(repeating: "a", count: 64), before: nil, limit: 5).isEmpty, "history reads under the unlock")
    do {
        _ = try restarted.sendText(peer: String(repeating: "b", count: 64), text: "hi", now: 0)
        check(false, "a stranger is refused")
    } catch CoreError.NotAFriend {
        check(true, "sending to a stranger is CoreError.NotAFriend")
    }
    _ = restarted.lock()
    check((try? restarted.history(peer: String(repeating: "a", count: 64), before: nil, limit: 5)) == nil, "locked again")
} catch {
    check(false, "unexpected error: \(error)")
}

print(failures == 0 ? "\nall checks passed" : "\n\(failures) check(s) FAILED")
exit(failures == 0 ? 0 : 1)
