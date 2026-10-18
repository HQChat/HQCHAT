//! The KEM the ratchet, the handshake and hqn/1 ride on: HQC-256 in
//! production, a fast stub in engine tests. Mirrors the TS `Kem` interface.

use hqc::{Ciphertext, KeyPair, PublicKey, SecretKey, SharedSecret};

use crate::Error;

/// A key-encapsulation mechanism.
pub trait Kem {
    /// A fresh keypair: ratchet keys, prekeys.
    fn generate_keypair(&self) -> Result<KeyPair, Error>;
    /// A fresh ciphertext for `pk` and the secret it carries.
    fn encapsulate(&self, pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), Error>;
    /// The secret `ct` carries for `sk`; implicit rejection, never an error on
    /// a forged ciphertext.
    fn decapsulate(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret, Error>;
}

/// HQC-256 over the pinned C reference implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct HqcKem;

impl Kem for HqcKem {
    fn generate_keypair(&self) -> Result<KeyPair, Error> {
        Ok(hqc::generate_keypair()?)
    }

    fn encapsulate(&self, pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), Error> {
        Ok(hqc::encapsulate(pk)?)
    }

    fn decapsulate(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret, Error> {
        Ok(hqc::decapsulate(sk, ct)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hqc_round_trips_through_the_trait() {
        let kem: &dyn Kem = &HqcKem;
        let pair = kem.generate_keypair().unwrap();
        let (ct, ss) = kem.encapsulate(&pair.public).unwrap();
        let opened = kem.decapsulate(&pair.secret, &ct).unwrap();
        assert_eq!(opened.as_bytes(), ss.as_bytes());
    }
}
