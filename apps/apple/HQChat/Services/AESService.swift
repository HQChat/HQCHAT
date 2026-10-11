import Foundation
import CryptoKit

/// AES-256-GCM Encryption Service
/// Handles fast symmetric encryption for message content
class AESService {
    
    /// Encrypt plaintext using AES-256-GCM
    /// Format: [IV (12 bytes)][Tag (16 bytes)][Ciphertext] encoded as Base64
    /// - Parameters:
    ///   - plaintext: Text to encrypt
    ///   - key: Symmetric key (32 bytes for AES-256)
    ///   - aad: Cleartext to bind but not carry — the frame header, whose fields
    ///     are read to CHOOSE the key and so cannot be authenticated by the
    ///     payload that key opens. Both peers must pass byte-identical bytes or
    ///     the tag check fails. Empty means plain AES-GCM, as before.
    /// - Returns: Base64-encoded encrypted data
    static func encrypt(plaintext: String, key: SymmetricKey, aad: Data = Data()) throws -> String {
        try encryptRaw(plaintext: plaintext, key: key, aad: aad).base64EncodedString()
    }

    /// Seals to raw bytes: `[IV 12][tag 16][ct]`. `encrypt` is its base64 form.
    static func encryptRaw(plaintext: String, key: SymmetricKey, aad: Data = Data()) throws -> Data {
        guard let plaintextData = plaintext.data(using: .utf8) else {
            throw AESError.invalidPlaintext
        }

        // Generate random IV (12 bytes for GCM)
        let iv = AES.GCM.Nonce()

        // Encrypt
        let sealedBox = try AES.GCM.seal(plaintextData, using: key,
                                         nonce: iv, authenticating: aad)

        // Format: [IV (12 bytes)][Tag (16 bytes)][Ciphertext]
        var result = Data(iv)
        result.append(sealedBox.tag)
        result.append(sealedBox.ciphertext)
        return result
    }
    
    /// Decrypt ciphertext using AES-256-GCM
    /// - Parameters:
    ///   - ciphertext: Base64-encoded encrypted data
    ///   - key: Symmetric key (32 bytes for AES-256)
    ///   - aad: Must be byte-identical to what the sender bound (see `encrypt`).
    /// - Returns: Decrypted plaintext string
    static func decrypt(ciphertext: String, key: SymmetricKey, aad: Data = Data()) throws -> String {
        guard let data = Data(base64Encoded: ciphertext) else {
            throw AESError.invalidCiphertext
        }
        return try decryptRaw(ciphertext: data, key: key, aad: aad)
    }

    /// `decrypt`, from the raw `[IV 12][tag 16][ct]` bytes a v3 frame carries.
    static func decryptRaw(ciphertext data: Data, key: SymmetricKey, aad: Data = Data()) throws -> String {
        guard data.count >= 28 else {  // 12 (IV) + 16 (tag) minimum
            throw AESError.invalidCiphertext
        }
        
        // Indexed from `startIndex`, not 0: the payload may be a slice of a frame.
        let base = data.startIndex
        let ivData = data[base..<(base + 12)]
        let tagData = Data(data[(base + 12)..<(base + 28)])
        let encryptedData = Data(data[(base + 28)..<data.endIndex])
        
        // Create nonce from IV
        guard let nonce = try? AES.GCM.Nonce(data: ivData) else {
            throw AESError.invalidIV
        }
        
        // Create sealed box
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: encryptedData, tag: tagData)
        
        // Decrypt
        let decryptedData = try AES.GCM.open(sealedBox, using: key, authenticating: aad)
        
        guard let plaintext = String(data: decryptedData, encoding: .utf8) else {
            throw AESError.decryptionFailed
        }
        
        return plaintext
    }
    
    /// Derive the shared per-friend AES key from the two KEM shared secrets using
    /// HKDF-SHA256. The secrets are sorted before derivation so both parties derive
    /// the same key regardless of who initiated. Inputs are the 32-byte KEM shared
    /// secrets — one we contributed (our encapsulation's `ss`) and one we
    /// decapsulated from the peer's ciphertext.
    /// - Returns: Symmetric key for AES-256
    static func deriveSharedKey(seedA: Data, seedB: Data) throws -> SymmetricKey {
        guard !seedA.isEmpty, !seedB.isEmpty else {
            throw AESError.invalidSeedSize
        }

        // Sort byte-by-byte for deterministic, order-independent derivation.
        let sortedSeeds = seedA.lexicographicallyPrecedes(seedB) ? [seedA, seedB] : [seedB, seedA]
        let combined = sortedSeeds[0] + sortedSeeds[1]

        // HKDF-SHA256 with salt and info (matches the TS deriveSharedKey default).
        let salt = Data("salt".utf8)
        let info = "info".data(using: .utf8)!

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: combined),
            salt: salt,
            info: info,
            outputByteCount: 32  // AES-256 requires 32 bytes
        )
    }

    /// Auth proof from a KEM shared secret. Mirrors the server's
    /// `authProof(ss)` in src/protocol/auth-proof.ts:
    /// HKDF-SHA256(IKM=ss, salt="salt", info="auth", 32). Returned as raw Data to
    /// base64-encode into the AUTH_VERIFY payload; proves we hold the secret key
    /// (only it could decapsulate `ss`) without ever revealing `ss`.
    static func authProof(ss: Data) -> Data {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ss),
            salt: Data("salt".utf8),
            info: Data("auth".utf8),
            outputByteCount: 32
        )
        return key.withUnsafeBytes { Data($0) }
    }

    /// Derive the per-direction client↔server transport keys from the session
    /// seed exchanged via HQC. Must match the server/bot:
    /// HKDF-SHA256(IKM=seed, salt="salt", info="session-c2s"/"session-s2c", 32).
    /// c2s: this client encrypts / server decrypts. s2c: the reverse.
    static func deriveSessionKeys(seed: Data) -> (c2s: SymmetricKey, s2c: SymmetricKey) {
        let salt = Data("salt".utf8)
        func key(_ dir: String) -> SymmetricKey {
            HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: seed),
                salt: salt,
                info: Data(("session-" + dir).utf8),
                outputByteCount: 32
            )
        }
        return (c2s: key("c2s"), s2c: key("s2c"))
    }
}

// MARK: - Errors

enum AESError: LocalizedError {
    case invalidPlaintext
    case invalidCiphertext
    case invalidIV
    case invalidSeedSize
    case encryptionFailed
    case decryptionFailed
    
    var errorDescription: String? {
        switch self {
        case .invalidPlaintext:
            return "Invalid plaintext encoding"
        case .invalidCiphertext:
            return "Invalid ciphertext format"
        case .invalidIV:
            return "Invalid initialization vector"
        case .invalidSeedSize:
            return "Shared secrets must be non-empty"
        case .encryptionFailed:
            return "AES encryption failed"
        case .decryptionFailed:
            return "AES decryption failed"
        }
    }
}
