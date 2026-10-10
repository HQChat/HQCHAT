#include <stdlib.h>
#include <string.h>
#include "hqc.h"      /* PARAM_*, SEED_BYTES, ciphertext_pke_t, hqc_pke_keygen, crypto_kem_* */
#include "api.h"      /* CRYPTO_PUBLICKEYBYTES / SECRETKEYBYTES / BYTES / CIPHERTEXTBYTES */

/*
 * HQC IND-CCA2 KEM wrappers, compiled with the upstream reference core
 * (src/common, src/ref, fips202) by native/hqc/package.nix and build-apple.sh.
 *
 * All three return an int status (0 = OK) and write into CALLER-allocated buffers
 * (no malloc → the TS/Swift side never cross-module free()s our memory).
 *
 *   keypair : DETERMINISTIC from the 32-byte identity seed; the public key is
 *             byte-identical to the pre-KEM build for the same seed (no pk churn).
 *   enc     : encapsulate to `pk` with fresh OS entropy → (ct, ss).
 *   dec     : decapsulate → ss (constant-time; masked implicit rejection).
 *
 * Sizes (HQC-256): pk 7237, sk 7333, ct 14421, shared secret 32.
 */

int hqc_kem_keypair_wrap(const uint8_t seed[SEED_BYTES],
                         uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                         uint8_t sk[CRYPTO_SECRETKEYBYTES]);

int hqc_kem_enc_wrap(uint8_t ct[CRYPTO_CIPHERTEXTBYTES],
                     uint8_t ss[CRYPTO_BYTES],
                     const uint8_t pk[CRYPTO_PUBLICKEYBYTES]);

int hqc_kem_dec_wrap(uint8_t ss[CRYPTO_BYTES],
                     const uint8_t ct[CRYPTO_CIPHERTEXTBYTES],
                     const uint8_t sk[CRYPTO_SECRETKEYBYTES]);
