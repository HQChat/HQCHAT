//! The two callbacks a shell implements. Both are local and fast, so they
//! are synchronous: the engine never waits on them across a suspension.

/// How strongly the device key is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// In hardware (Secure Enclave, StrongBox/TEE, TPM 2.0) behind biometrics.
    Hardware,
    /// In hardware behind the device passcode only (Apple's reduced tier).
    HardwarePasscode,
    /// No hardware available: sealed under a passphrase. Warned, not penalised.
    Software,
}

/// Why a vault call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// The user has not unlocked, or dismissed the prompt.
    Locked,
    /// There is no device key yet.
    Missing,
    /// The key exists but the platform refused it (deleted biometrics, a TPM
    /// that disappeared).
    Unavailable(String),
}

/// The device key: a P-256 key that never leaves the chip. The engine does
/// ECIES itself: sealing needs only [`KeyVault::device_public_key`], so it
/// works while locked; opening needs one [`KeyVault::agree`].
pub trait KeyVault: Send + Sync {
    /// Creates the device key if there is none; returns the tier it got.
    fn create(&self) -> Result<Tier, VaultError>;

    /// The device public key, 65-byte uncompressed P-256.
    fn device_public_key(&self) -> Result<Vec<u8>, VaultError>;

    /// One ECDH between the device key and `ephemeral_public` (65 bytes),
    /// under the context the shell authenticated before calling
    /// `Engine::unlock`. Returns the 32-byte shared secret.
    fn agree(&self, ephemeral_public: Vec<u8>) -> Result<Vec<u8>, VaultError>;

    /// A 32-byte secret kept beside the device key, under the same
    /// protection, and readable only under the same authenticated context as
    /// [`KeyVault::agree`]. It joins the ECDH secret in sealing `state` (the
    /// identity and the data key), so what is stored does not rest on P-256
    /// alone: a quantum computer that breaks it still lacks this.
    fn state_secret(&self) -> Result<Vec<u8>, VaultError>;

    /// The device key's tier, as stored next to it.
    fn tier(&self) -> Tier;
}

/// Why a store call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The disk is full or the write failed.
    Write(String),
}

/// Opaque blobs by key. Everything the engine stores is already sealed; the
/// shell never parses it.
pub trait Store: Send + Sync {
    /// The blob under `key`.
    fn get(&self, key: String) -> Option<Vec<u8>>;
    /// Stores `value` under `key`, replacing any blob there. Durable on return.
    fn put(&self, key: String, value: Vec<u8>) -> Result<(), StoreError>;
    /// Removes the blob under `key`.
    fn delete(&self, key: String);
    /// Every key starting with `prefix`, sorted.
    fn list(&self, prefix: String) -> Vec<String>;
}
