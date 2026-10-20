//! HQC-256, the KEM under every HQChat key agreement (sign-in, prekeys, the
//! ratchet, the handshake, hqn/1), over the pinned C reference
//! implementation in `hqc-sys`.
//!
//! - Keys and ciphertexts are fixed-size types, so a wrong length is caught
//!   once, at [`PublicKey::from_bytes`] and friends, never inside C.
//! - [`SecretKey`], [`SharedSecret`] and [`Seed`] are wiped when dropped and
//!   never printed.
//! - [`encapsulate`] draws its entropy from the OS; [`encapsulate_derand`]
//!   takes it from the caller, for known-answer tests and vectors only.
//! - Decapsulation never fails on a forged ciphertext: implicit rejection
//!   returns a pseudo-random secret, so there is no decryption oracle.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use hqc_sys::{
    CIPHERTEXT_BYTES, ENC_ENTROPY_BYTES, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SEED_BYTES,
    SHARED_SECRET_BYTES,
};

/// Why an HQC call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A byte string had the wrong length for what it claims to be.
    Length {
        /// What was being read ("public key", "ciphertext", …).
        what: &'static str,
        /// The length HQC-256 needs.
        expected: usize,
        /// The length given.
        got: usize,
    },
    /// The OS random generator failed.
    Entropy,
    /// The C library returned a non-zero status.
    Native {
        /// The operation that failed.
        op: &'static str,
        /// Its status code.
        status: i32,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Length {
                what,
                expected,
                got,
            } => {
                write!(f, "HQC {what} must be {expected} bytes, got {got}")
            }
            Error::Entropy => f.write_str("the OS random generator failed"),
            Error::Native { op, status } => write!(f, "HQC {op} failed (status {status})"),
        }
    }
}

impl std::error::Error for Error {}

fn check(op: &'static str, status: i32) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Native { op, status })
    }
}

fn exact<const N: usize>(what: &'static str, bytes: &[u8]) -> Result<Box<[u8; N]>, Error> {
    let mut out = Box::new([0u8; N]);
    if bytes.len() != N {
        return Err(Error::Length {
            what,
            expected: N,
            got: bytes.len(),
        });
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

/// An HQC-256 public key (7,237 bytes). A client's id is the SHA-256 of its hex.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(Box<[u8; PUBLIC_KEY_BYTES]>);

impl PublicKey {
    /// Reads a public key; fails on any length but [`PUBLIC_KEY_BYTES`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        exact("public key", bytes).map(Self)
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey({:02x?}…)",
            self.0.get(..8).unwrap_or_default()
        )
    }
}

/// An HQC-256 secret key (7,333 bytes). Wiped on drop, never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Box<[u8; SECRET_KEY_BYTES]>);

impl SecretKey {
    /// Reads a secret key; fails on any length but [`SECRET_KEY_BYTES`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        exact("secret key", bytes).map(Self)
    }

    /// The key's bytes, for sealing it at rest. Handle with care.
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_BYTES] {
        &self.0
    }

    /// Whether `public` is this key's public half. An HQC-KEM secret key
    /// starts with its public key (`dk_kem = ek_kem ‖ dk_pke ‖ σ ‖ seed_kem`),
    /// so a pair read from outside is checked without a KEM round trip.
    pub fn belongs_to(&self, public: &PublicKey) -> bool {
        self.0.first_chunk::<PUBLIC_KEY_BYTES>() == Some(&*public.0)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(…)")
    }
}

/// An HQC-256 KEM ciphertext (14,421 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext(Box<[u8; CIPHERTEXT_BYTES]>);

impl Ciphertext {
    /// Reads a ciphertext; fails on any length but [`CIPHERTEXT_BYTES`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        exact("ciphertext", bytes).map(Self)
    }

    /// The ciphertext's bytes.
    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_BYTES] {
        &self.0
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ciphertext({:02x?}…)",
            self.0.get(..8).unwrap_or_default()
        )
    }
}

/// The 32-byte secret a KEM exchange agrees on; callers stretch it with HKDF.
/// Wiped on drop, never printed, compared in constant time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; SHARED_SECRET_BYTES]);

impl SharedSecret {
    /// A secret from known bytes: vectors that pin what a KDF makes of a
    /// given secret. A real secret comes from [`encapsulate`] or
    /// [`decapsulate`].
    pub fn from_bytes(bytes: [u8; SHARED_SECRET_BYTES]) -> Self {
        Self(bytes)
    }

    /// The secret's bytes, to feed a KDF.
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
        &self.0
    }
}

impl ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(…)")
    }
}

/// A 32-byte seed a keypair is derived from, deterministically. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; SEED_BYTES]);

impl Seed {
    /// A fresh seed from the OS random generator.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = [0u8; SEED_BYTES];
        getrandom::fill(&mut seed).map_err(|_| Error::Entropy)?;
        Ok(Self(seed))
    }

    /// A seed from known bytes (a stored identity seed, a test vector).
    pub fn from_bytes(bytes: [u8; SEED_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(…)")
    }
}

/// A public key and its secret key.
#[derive(Clone, Debug)]
pub struct KeyPair {
    /// The half that is published.
    pub public: PublicKey,
    /// The half that never leaves the device.
    pub secret: SecretKey,
}

/// The keypair a seed determines: the same seed gives the same identity on
/// every platform and every shipped client.
pub fn keypair_from_seed(seed: &Seed) -> Result<KeyPair, Error> {
    let mut public = Box::new([0u8; PUBLIC_KEY_BYTES]);
    let mut secret = SecretKey(Box::new([0u8; SECRET_KEY_BYTES]));
    check(
        "keypair",
        hqc_sys::keypair(&seed.0, &mut public, &mut secret.0),
    )?;
    Ok(KeyPair {
        public: PublicKey(public),
        secret,
    })
}

/// A keypair from a fresh random seed: prekeys and ratchet keys.
pub fn generate_keypair() -> Result<KeyPair, Error> {
    keypair_from_seed(&Seed::generate()?)
}

/// A fresh ciphertext for `pk` and the secret it carries, with entropy from
/// the OS.
pub fn encapsulate(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), Error> {
    let mut entropy = Entropy([0u8; ENC_ENTROPY_BYTES]);
    getrandom::fill(&mut entropy.0).map_err(|_| Error::Entropy)?;
    encapsulate_derand(pk, &entropy.0)
}

/// [`encapsulate`] with the caller's entropy: the same entropy gives the same
/// ciphertext. For known-answer tests and vectors only; reusing entropy
/// across real encapsulations gives the secret away.
pub fn encapsulate_derand(
    pk: &PublicKey,
    entropy: &[u8; ENC_ENTROPY_BYTES],
) -> Result<(Ciphertext, SharedSecret), Error> {
    let mut ct = Box::new([0u8; CIPHERTEXT_BYTES]);
    let mut ss = SharedSecret([0u8; SHARED_SECRET_BYTES]);
    check(
        "encapsulate",
        hqc_sys::encapsulate_derand(&mut ct, &mut ss.0, &pk.0, entropy),
    )?;
    Ok((Ciphertext(ct), ss))
}

/// The secret `ct` carries for `sk`. A forged or corrupted ciphertext yields
/// a pseudo-random secret rather than an error (implicit rejection), so the
/// mismatch surfaces later, when a key derived from it fails to authenticate.
pub fn decapsulate(sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret, Error> {
    let mut ss = SharedSecret([0u8; SHARED_SECRET_BYTES]);
    check("decapsulate", hqc_sys::decapsulate(&mut ss.0, &ct.0, &sk.0))?;
    Ok(ss)
}

/// Encapsulation entropy on the stack, wiped when it goes out of scope.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Entropy([u8; ENC_ENTROPY_BYTES]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_length_is_refused_with_what_and_how_long() {
        assert_eq!(
            PublicKey::from_bytes(&[0u8; 10]).unwrap_err(),
            Error::Length {
                what: "public key",
                expected: PUBLIC_KEY_BYTES,
                got: 10
            }
        );
        assert!(SecretKey::from_bytes(&[0u8; PUBLIC_KEY_BYTES]).is_err());
        assert!(Ciphertext::from_bytes(&[]).is_err());
    }

    #[test]
    fn secrets_never_print() {
        let pair = keypair_from_seed(&Seed::from_bytes([7; SEED_BYTES])).unwrap();
        assert_eq!(format!("{:?}", pair.secret), "SecretKey(…)");
        assert_eq!(
            format!("{:?}", Seed::from_bytes([7; SEED_BYTES])),
            "Seed(…)"
        );
    }
}
