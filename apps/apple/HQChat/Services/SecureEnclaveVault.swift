import Foundation
import HQChatCore

/// The core's `KeyVault` on the Secure Enclave: the profile's existing Enclave
/// key (`MessageKeyStore`), so the core seals at rest to the same key, under
/// the same tier, opened by the same unlock as the app's message keys.
///
/// The core does its own ECIES (an ephemeral P-256 key, HKDF, AES-GCM); all it
/// asks of the vault is the public half, which needs no user, and one ECDH,
/// which needs the session's unlock. There is deliberately no software
/// fallback on Apple: every device the app supports has an Enclave, and the
/// Simulator has none, as the app's key store already states.
final class SecureEnclaveVault: KeyVault, @unchecked Sendable {
    private let profileID: UUID

    init(profileID: UUID) {
        self.profileID = profileID
    }

    func create() throws -> Tier {
        guard MessageKeyStore.devicePublicKey(for: profileID) != nil else {
            throw VaultError.Unavailable(message: "the Secure Enclave key could not be created")
        }
        return tier()
    }

    func devicePublicKey() throws -> Data {
        guard let key = MessageKeyStore.devicePublicKey(for: profileID) else { throw VaultError.Missing }
        return key
    }

    func agree(ephemeralPublic: Data) throws -> Data {
        do {
            return try MessageKeyStore.agree(ephemeralPublic: ephemeralPublic, for: profileID)
        } catch MessageKeyStore.AgreementError.locked {
            throw VaultError.Locked
        } catch MessageKeyStore.AgreementError.missing {
            throw VaultError.Missing
        } catch {
            throw VaultError.Unavailable(message: "the Secure Enclave refused the agreement: \(error)")
        }
    }

    /// The key's protection as the core names it: behind biometrics, or behind
    /// any device-owner authentication (the passcode included).
    func tier() -> Tier {
        switch KeyProtectionTier.stored(for: profileID.uuidString) {
        case .biometryCurrentSet: return .hardware
        case .userPresence: return .hardwarePasscode
        }
    }
}
