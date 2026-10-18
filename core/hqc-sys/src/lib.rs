//! The HQC-256 KEM from C, through `csrc/hqc_sys.c`: keygen and
//! decapsulation are `native/hqc/src/low_wrap.c`'s, encapsulation takes
//! caller-supplied entropy, and every call zeroes the stack HQC used before
//! it returns. The functions at the root are safe: fixed-size arrays give
//! every pointer the length the C expects, and encapsulations are serialized
//! here because HQC's PRNG is process-global. The `hqc` crate builds the
//! typed API on them; [`ffi`] is the raw C, for this crate alone.
//!
//! `low_wrap.c`'s own functions are deliberately not declared: calling them
//! directly would skip the stack scrub, and `hqc_kem_enc_wrap` also draws
//! entropy inside C and leaves the PRNG state in memory (see
//! `csrc/hqc_sys.c`).

use std::ffi::c_int;
use std::sync::Mutex;

/// Public key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = 7237;
/// Secret key length in bytes.
pub const SECRET_KEY_BYTES: usize = 7333;
/// Ciphertext length in bytes.
pub const CIPHERTEXT_BYTES: usize = 14421;
/// Shared secret length in bytes.
pub const SHARED_SECRET_BYTES: usize = 32;
/// Identity seed length in bytes.
pub const SEED_BYTES: usize = 32;
/// Entropy one encapsulation consumes: the message (32) and the salt (16).
pub const ENC_ENTROPY_BYTES: usize = 48;

/// Held for every encapsulation: HQC's PRNG is one global SHAKE-256 state.
static ENC_LOCK: Mutex<()> = Mutex::new(());

/// Deterministic keypair from a 32-byte seed. Returns the C status, 0 on success.
pub fn keypair(
    seed: &[u8; SEED_BYTES],
    pk: &mut [u8; PUBLIC_KEY_BYTES],
    sk: &mut [u8; SECRET_KEY_BYTES],
) -> c_int {
    // SAFETY: each array is exactly the length the C reads or writes; keygen
    // does not touch the global PRNG.
    unsafe { ffi::hqc_sys_kem_keypair(seed.as_ptr(), pk.as_mut_ptr(), sk.as_mut_ptr()) }
}

/// Encapsulates to `pk` with `entropy` seeding the PRNG, which is wiped
/// afterwards. Returns the C status, 0 on success.
pub fn encapsulate_derand(
    ct: &mut [u8; CIPHERTEXT_BYTES],
    ss: &mut [u8; SHARED_SECRET_BYTES],
    pk: &[u8; PUBLIC_KEY_BYTES],
    entropy: &[u8; ENC_ENTROPY_BYTES],
) -> c_int {
    // A panic while held leaves nothing half-done in the PRNG that the next
    // call relies on: every call reseeds it.
    let _held = ENC_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: each array is exactly the length the C reads or writes, and the
    // lock keeps any other encapsulation off the global PRNG.
    unsafe {
        ffi::hqc_sys_kem_enc_derand(
            ct.as_mut_ptr(),
            ss.as_mut_ptr(),
            pk.as_ptr(),
            entropy.as_ptr(),
        )
    }
}

/// Decapsulates `ct` with `sk`: constant time with implicit rejection, so a
/// forged ciphertext yields a pseudo-random secret and still returns 0.
pub fn decapsulate(
    ss: &mut [u8; SHARED_SECRET_BYTES],
    ct: &[u8; CIPHERTEXT_BYTES],
    sk: &[u8; SECRET_KEY_BYTES],
) -> c_int {
    // SAFETY: each array is exactly the length the C reads or writes;
    // decapsulation does not touch the global PRNG.
    unsafe { ffi::hqc_sys_kem_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) }
}

/// The sizes the C was compiled with: public key, secret key, ciphertext,
/// shared secret, encapsulation entropy.
pub fn compiled_sizes() -> [usize; 5] {
    let mut sizes = [0usize; 5];
    // SAFETY: five writable usize.
    unsafe { ffi::hqc_sys_sizes(sizes.as_mut_ptr()) };
    sizes
}

/// The C functions. Call the safe wrappers above instead.
pub mod ffi {
    use std::ffi::c_int;

    unsafe extern "C" {
        /// Deterministic keypair from a 32-byte seed, then a stack scrub.
        /// Returns 0 on success.
        ///
        /// # Safety
        /// `seed` must point to `SEED_BYTES` readable bytes, `pk` to
        /// `PUBLIC_KEY_BYTES` and `sk` to `SECRET_KEY_BYTES` writable bytes.
        pub fn hqc_sys_kem_keypair(seed: *const u8, pk: *mut u8, sk: *mut u8) -> c_int;

        /// Encapsulates to `pk` with `entropy` as the PRNG seed, then wipes the
        /// PRNG state and the stack. Returns 0 on success.
        ///
        /// # Safety
        /// `ct` must point to `CIPHERTEXT_BYTES` and `ss` to
        /// `SHARED_SECRET_BYTES` writable bytes, `pk` to `PUBLIC_KEY_BYTES` and
        /// `entropy` to `ENC_ENTROPY_BYTES` readable bytes. No other
        /// encapsulation may run at the same time: the PRNG is process-global.
        pub fn hqc_sys_kem_enc_derand(
            ct: *mut u8,
            ss: *mut u8,
            pk: *const u8,
            entropy: *const u8,
        ) -> c_int;

        /// Decapsulates `ct` with `sk`, then a stack scrub.
        ///
        /// # Safety
        /// `ss` must point to `SHARED_SECRET_BYTES` writable bytes, `ct` to
        /// `CIPHERTEXT_BYTES` and `sk` to `SECRET_KEY_BYTES` readable bytes.
        pub fn hqc_sys_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;

        /// Writes the compiled sizes.
        ///
        /// # Safety
        /// `out` must point to 5 writable `usize`.
        pub fn hqc_sys_sizes(out: *mut usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_constants_match_the_compiled_c() {
        assert_eq!(
            compiled_sizes(),
            [
                PUBLIC_KEY_BYTES,
                SECRET_KEY_BYTES,
                CIPHERTEXT_BYTES,
                SHARED_SECRET_BYTES,
                ENC_ENTROPY_BYTES
            ]
        );
    }
}
