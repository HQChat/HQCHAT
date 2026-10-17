// Per-friend ratchet sessions and per-profile prekey secrets, in the Keychain
// instead of the (plaintext) SwiftData store, so the message database never
// contains the keys needed to decrypt it.
//
// Items need the user: they carry the profile's protection tier as an ACL, the
// same tier as the identity and message keys, and are read through the one
// authenticated context `MessageKeyStore` holds. Nothing here ever prompts.
//
// That is affordable because nothing decrypts without the user any more. An
// inbound frame is admitted as ciphertext (ConversationRouter, `PendingFrame`)
// and opened once the user has unlocked; the notification it raises never
// carried plaintext anyway.
//
// A locked read is `.locked`, never "absent". The difference is the whole point:
// a caller that took a locked session for a missing one would start a new
// session over it, or mint prekeys over secrets peers still hold.

import Foundation
import Security
import LocalAuthentication

/// What one Keychain read found.
enum KeyRead: Equatable {
    case value(Data)
    /// Nothing is stored under this account.
    case absent
    /// Something is stored and the user has not unlocked it. Callers must not
    /// treat this as `absent`.
    case locked

    var data: Data? {
        if case .value(let data) = self { return data }
        return nil
    }
}

/// Where `AESKeyStore` keeps its items. The Keychain in the app; an in-memory
/// store in the swiftc-built tests, whose unsigned binaries cannot write ACL'd
/// items (-34018).
protocol AESKeyBackend: AnyObject {
    func read(_ account: String) -> KeyRead
    /// Whether an item exists, answered without authenticating.
    func exists(_ account: String) -> Bool
    /// Writes `data`, replacing any item in place. False when nothing was written.
    func write(_ data: Data, account: String) -> Bool
    func delete(_ account: String)
    /// Every account stored, read without authenticating.
    func accounts() -> [String]
}

enum AESKeyStore {
    /// The service items were stored under before they carried an ACL. Still
    /// read, to migrate them on the first unlock; never written.
    static let service = "app.hqchat.aeskeys"
    /// The service of the protected items.
    static let protectedService = "app.hqchat.aeskeys.v2"

    static var backend: AESKeyBackend = KeychainAESBackend.protected
    static var legacy: AESKeyBackend = KeychainAESBackend.legacy
    /// Whether reads and writes can succeed right now: the user has unlocked and
    /// the context is held.
    static var isUnlocked: () -> Bool = { MessageKeyStore.canRead }

    static func read(_ account: String) -> KeyRead {
        // Not left to the ACL alone: the Simulator does not enforce it, and a
        // read that succeeded there while locked would behave unlike a device.
        guard isUnlocked() else { return exists(account) ? .locked : .absent }
        let found = backend.read(account)
        guard found == .absent, legacy.exists(account) else { return found }
        // Written before items carried an ACL: moved on first use.
        return migrate(account) ? backend.read(account) : .locked
    }

    /// Whether an item exists. Needs no unlock, so a view can ask.
    static func exists(_ account: String) -> Bool {
        backend.exists(account) || legacy.exists(account)
    }

    /// Stores `data`, or deletes the item for nil. Refuses to write while
    /// locked: every value written is derived from one read, and a locked read
    /// has nothing to derive from.
    @discardableResult
    static func set(_ data: Data?, account: String) -> Bool {
        guard let data else {
            delete(account)
            return true
        }
        guard isUnlocked() else {
            Log.keys.error("[AESKeyStore] ❌ write refused while locked — nothing derived from a locked read is stored")
            return false
        }
        guard backend.write(data, account: account) else { return false }
        legacy.delete(account)
        return true
    }

    static func delete(_ account: String) {
        backend.delete(account)
        legacy.delete(account)
    }

    /// Moves every unprotected item of `profileID` under the ACL. Run on unlock,
    /// so the unprotected copies do not wait for their first use to disappear.
    /// Returns how many moved.
    @discardableResult
    static func migrateLegacyItems(profileID: UUID) -> Int {
        guard isUnlocked() else { return 0 }
        let id = profileID.uuidString
        var moved = 0
        for account in legacy.accounts() where account.contains(id) {
            if migrate(account) { moved += 1 }
        }
        if moved > 0 {
            Log.keys.info("[AESKeyStore] 🔐 moved \(moved) key item(s) under the profile's protection")
        }
        return moved
    }

    /// Copies one legacy item under the ACL, then deletes the legacy copy. A
    /// crash in between leaves both, and the next pass only deletes.
    private static func migrate(_ account: String) -> Bool {
        if backend.exists(account) {
            legacy.delete(account)
            return true
        }
        guard let data = legacy.read(account).data,
              backend.write(data, account: account) else { return false }
        legacy.delete(account)
        return true
    }
}

/// The Keychain behind `AESKeyStore`.
final class KeychainAESBackend: AESKeyBackend {
    static let protected = KeychainAESBackend(service: AESKeyStore.protectedService, isProtected: true)
    static let legacy = KeychainAESBackend(service: AESKeyStore.service, isProtected: false)

    private let service: String
    /// Protected items live in the data protection keychain (which ACLs need on
    /// macOS) and carry the tier. Legacy items are read and deleted only.
    private let isProtected: Bool

    private init(service: String, isProtected: Bool) {
        self.service = service
        self.isProtected = isProtected
    }

    private func base(_ account: String? = nil) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        if let account { query[kSecAttrAccount as String] = account }
        if isProtected { query[kSecUseDataProtectionKeychain as String] = true }
        return query
    }

    /// The held context, or one that answers `errSecInteractionNotAllowed`
    /// rather than prompting.
    private func context() -> LAContext {
        MessageKeyStore.sharedAuthenticatedContext() ?? LAContext.nonInteractive()
    }

    func read(_ account: String) -> KeyRead {
        var query = base(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if isProtected { query[kSecUseAuthenticationContext as String] = context() }
        var result: AnyObject?
        let status = BiometricAudit.measure("SecItemCopyMatching",
                                            item: isProtected ? "ratchet/prekey state (AESKeyStore)"
                                                              : "legacy ratchet/prekey state",
                                            expectsPrompt: false) {
            SecItemCopyMatching(query as CFDictionary, &result)
        }
        switch status {
        case errSecSuccess:
            return (result as? Data).map(KeyRead.value) ?? .locked
        case errSecItemNotFound:
            return .absent
        default:
            // errSecInteractionNotAllowed / errSecAuthFailed: the user has not
            // unlocked. Anything else is treated the same way: failing closed
            // costs a deferred frame, failing open would cost the session.
            return .locked
        }
    }

    func exists(_ account: String) -> Bool {
        var query = base(account)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if isProtected { query[kSecUseAuthenticationContext as String] = LAContext.nonInteractive() }
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    func write(_ data: Data, account: String) -> Bool {
        // Legacy items are never written: they are what is being migrated away from.
        guard isProtected else { return false }
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            MessageKeyStore.currentTier.accessControlFlag, nil
        ) else { return false }

        // Updated in place, so there is no moment with no item: a delete-then-add
        // that failed halfway would lose the session.
        var match = base(account)
        match[kSecUseAuthenticationContext as String] = context()
        let updated = SecItemUpdate(match as CFDictionary,
                                    [kSecValueData as String: data] as CFDictionary)
        if updated == errSecSuccess { return true }
        guard updated == errSecItemNotFound else {
            Log.keys.error("[AESKeyStore] ❌ update failed (\(updated))")
            return false
        }

        var add = base(account)
        add[kSecValueData as String] = data
        add[kSecAttrAccessControl as String] = access
        add[kSecUseAuthenticationContext as String] = context()
        let added = SecItemAdd(add as CFDictionary, nil)
        if added != errSecSuccess {
            Log.keys.error("[AESKeyStore] ❌ add failed (\(added))")
        }
        return added == errSecSuccess
    }

    func delete(_ account: String) {
        SecItemDelete(base(account) as CFDictionary)
    }

    func accounts() -> [String] {
        var query = base()
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        if isProtected { query[kSecUseAuthenticationContext as String] = LAContext.nonInteractive() }
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let rows = result as? [[String: Any]] else { return [] }
        return rows.compactMap { $0[kSecAttrAccount as String] as? String }
    }
}
