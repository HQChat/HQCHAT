// TRANSITION CODE (see CoreImport.swift): the Keychain items 3.1.1 kept, read
// once by the move to the core and then deleted. Nothing here writes.
//
// - the identity's HQC secret key, behind the profile's protection tier
//   (`app.hqchat.profile.<id>`);
// - ratchet sessions and prekey secrets (`AESKeyStore`), behind the same tier
//   and read through the context the unlock holds.
//
// A locked read is `.locked`, never "absent": the move must not take a locked
// session for a missing one.

import Foundation
import LocalAuthentication
import Security

/// What one Keychain read found.
enum KeyRead: Equatable {
    case value(Data)
    /// Nothing is stored under this account.
    case absent
    /// Something is stored and the user has not unlocked it.
    case locked

    var data: Data? {
        if case .value(let data) = self { return data }
        return nil
    }
}

/// Sessions and prekey secrets as 3.1.1 stored them.
enum AESKeyStore {
    /// Items from before they carried an ACL; read as a fallback.
    static let service = "app.hqchat.aeskeys"
    static let protectedService = "app.hqchat.aeskeys.v2"

    /// Whether reads can succeed now: the user has unlocked.
    static var isUnlocked: () -> Bool = { MessageKeyStore.canRead }

    static func read(_ account: String) -> KeyRead {
        let read = item(protectedService, account, protected: true)
        if read == .absent { return item(service, account, protected: false) }
        return read
    }

    static func delete(_ account: String) {
        for (svc, protected) in [(protectedService, true), (service, false)] {
            SecItemDelete(query(svc, account, protected: protected) as CFDictionary)
        }
    }

    /// Every account `profileID` stored, read without authenticating.
    static func accounts(of profileID: UUID) -> [String] {
        var all: [String] = []
        for (svc, protected) in [(protectedService, true), (service, false)] {
            var q = query(svc, nil, protected: protected)
            q[kSecReturnAttributes as String] = true
            q[kSecMatchLimit as String] = kSecMatchLimitAll
            if protected { q[kSecUseAuthenticationContext as String] = LAContext.nonInteractive() }
            var result: AnyObject?
            guard SecItemCopyMatching(q as CFDictionary, &result) == errSecSuccess,
                  let rows = result as? [[String: Any]] else { continue }
            all += rows.compactMap { $0[kSecAttrAccount as String] as? String }
        }
        return all.filter { $0.contains(profileID.uuidString) }
    }

    private static func query(_ service: String, _ account: String?, protected: Bool) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        if let account { q[kSecAttrAccount as String] = account }
        if protected { q[kSecUseDataProtectionKeychain as String] = true }
        return q
    }

    private static func item(_ service: String, _ account: String, protected: Bool) -> KeyRead {
        var q = query(service, account, protected: protected)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        if protected {
            q[kSecUseAuthenticationContext as String] =
                MessageKeyStore.sharedAuthenticatedContext() ?? LAContext.nonInteractive()
        }
        var result: AnyObject?
        let status = BiometricAudit.measure("SecItemCopyMatching", item: "3.1.1 session/prekeys",
                                            expectsPrompt: false) {
            SecItemCopyMatching(q as CFDictionary, &result)
        }
        switch status {
        case errSecSuccess: return (result as? Data).map(KeyRead.value) ?? .locked
        case errSecItemNotFound: return .absent
        default: return .locked
        }
    }
}

/// The 3.1.1 identity key.
enum LegacyIdentity {
    private static func service(_ profileID: UUID) -> String { "app.hqchat.profile.\(profileID.uuidString)" }

    /// Whether `profileID` has a 3.1.1 identity key, asked without prompting.
    static func exists(profileID: UUID) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service(profileID),
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: LAContext.nonInteractive(),
        ]
        var item: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// Reads the secret key. On a tier that holds its key for the session the
    /// unlock's context opens it; otherwise the Keychain asks once more, as
    /// 3.1.1 did for every sign-in.
    static func readSecretKey(profileID: UUID) -> Data? {
        let tier = KeyProtectionTier.stored(for: profileID.uuidString)
        let shared = tier.holdsKeyForSession ? MessageKeyStore.sharedAuthenticatedContext() : nil
        let context = shared ?? LAContext()
        context.localizedReason = "Update your HQChat data"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service(profileID),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context,
        ]
        var result: AnyObject?
        let status = BiometricCoordinator.withPrompt {
            BiometricAudit.measure("SecItemCopyMatching", item: "3.1.1 identity key", expectsPrompt: shared == nil) {
                SecItemCopyMatching(query as CFDictionary, &result)
            }
        }
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    static func delete(profileID: UUID) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service(profileID),
        ] as CFDictionary)
    }
}
