/*
 * The Rust core's entry points into HQC, compiled beside low_wrap.c.
 *
 * Keygen and decapsulation are low_wrap.c's, unchanged, so a seed yields the
 * same identity key as on every shipped client. Encapsulation is here instead
 * of hqc_kem_enc_wrap for two reasons:
 *
 *   - the caller supplies the entropy (the Rust side draws it from the OS
 *     with getrandom), so no platform depends on hqc_getrandom and a fixed
 *     entropy gives a known-answer test;
 *   - the PRNG is a process-global SHAKE-256 state (symmetric.c), and after
 *     crypto_kem_enc it still holds the sponge that produced m and the salt.
 *     Keccak is invertible, so that state gives the shared secret to anyone
 *     who reads the memory. It is wiped before returning.
 *
 * The PRNG is global: the caller must not run two encapsulations at once
 * (the `hqc` crate holds a lock). Keygen and decapsulation do not touch it.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "api.h"
#include "crypto_memset.h"
#include "parameters.h"
#include "symmetric.h"

/* symmetric.c's PRNG state; not declared in its header. */
extern shake256incctx shake256_prng_ctx;

#define HQC_SYS_ENC_ENTROPY_BYTES (PARAM_SECURITY_BYTES + SALT_BYTES)

int hqc_sys_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                           const uint8_t *entropy) {
    /* prng_init takes a mutable pointer; never hand it the caller's buffer. */
    uint8_t seed[HQC_SYS_ENC_ENTROPY_BYTES];
    memcpy(seed, entropy, sizeof seed);
    prng_init(seed, NULL, (uint32_t)sizeof seed, 0);
    int rc = crypto_kem_enc(ct, ss, pk);
    memset_volatile(&shake256_prng_ctx, 0, sizeof shake256_prng_ctx);
    memset_volatile(seed, 0, sizeof seed);
    return rc;
}

void hqc_sys_sizes(size_t out[5]) {
    out[0] = CRYPTO_PUBLICKEYBYTES;
    out[1] = CRYPTO_SECRETKEYBYTES;
    out[2] = CRYPTO_CIPHERTEXTBYTES;
    out[3] = CRYPTO_BYTES;
    out[4] = HQC_SYS_ENC_ENTROPY_BYTES;
}
