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
 *
 * Every entry point here also overwrites the stack the HQC call used before
 * returning: the reference code leaves secret-dependent buffers there (the
 * re-encryption inside decapsulation, the keygen vectors), and Rust cannot
 * wipe memory it never owned.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "api.h"
#include "wrapper.h"
#include "crypto_memset.h"
#include "parameters.h"
#include "symmetric.h"

/* symmetric.c's PRNG state; not declared in its header. */
extern shake256incctx shake256_prng_ctx;

#define HQC_SYS_ENC_ENTROPY_BYTES (PARAM_SECURITY_BYTES + SALT_BYTES)

/*
 * More than any HQC-256 call's stack: the deepest path, crypto_kem_dec ->
 * hqc_pke_encrypt -> vect_mul, takes about 210 KiB at -O2 (-fstack-usage,
 * clang and gcc). The calls run one after the other, so the peak stays near
 * 256 KiB, within every thread stack the core runs on (iOS secondary
 * threads have 512 KiB).
 */
#define HQC_SYS_SCRUB_BYTES (256u * 1024u)

#if defined(_MSC_VER)
#define HQC_SYS_NOINLINE __declspec(noinline)
#else
#define HQC_SYS_NOINLINE __attribute__((noinline))
#endif

/*
 * Zeroes the stack below the caller's frame. Not inlined, so its frame
 * starts where the HQC call's did and covers what that call left behind;
 * memset_volatile is a volatile function pointer, so the stores stay.
 */
static HQC_SYS_NOINLINE void hqc_sys_scrub_stack(void) {
    uint8_t region[HQC_SYS_SCRUB_BYTES];
    memset_volatile(region, 0, sizeof region);
}

int hqc_sys_kem_keypair(const uint8_t *seed, uint8_t *pk, uint8_t *sk) {
    int rc = hqc_kem_keypair_wrap(seed, pk, sk);
    hqc_sys_scrub_stack();
    return rc;
}

int hqc_sys_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    int rc = hqc_kem_dec_wrap(ss, ct, sk);
    hqc_sys_scrub_stack();
    return rc;
}

int hqc_sys_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                           const uint8_t *entropy) {
    /* prng_init takes a mutable pointer; never hand it the caller's buffer. */
    uint8_t seed[HQC_SYS_ENC_ENTROPY_BYTES];
    memcpy(seed, entropy, sizeof seed);
    prng_init(seed, NULL, (uint32_t)sizeof seed, 0);
    int rc = crypto_kem_enc(ct, ss, pk);
    memset_volatile(&shake256_prng_ctx, 0, sizeof shake256_prng_ctx);
    memset_volatile(seed, 0, sizeof seed);
    hqc_sys_scrub_stack();
    return rc;
}

void hqc_sys_sizes(size_t out[5]) {
    out[0] = CRYPTO_PUBLICKEYBYTES;
    out[1] = CRYPTO_SECRETKEYBYTES;
    out[2] = CRYPTO_CIPHERTEXTBYTES;
    out[3] = CRYPTO_BYTES;
    out[4] = HQC_SYS_ENC_ENTROPY_BYTES;
}
