#define __STDC_WANT_LIB_EXT1__ 1

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "wrapper.h"
#include "symmetric.h"       /* prng_init / prng_get_bytes / shake256_xof_ctx / xof_* */
#include "hqc_portability.h" /* hqc_getrandom — portable OS entropy (arc4random / getrandom) */

static void secure_memzero(void *ptr, size_t len)
{
#if defined(__STDC_LIB_EXT1__)
    (void)memset_s(ptr, len, 0, len);
#elif defined(__GNUC__) || defined(__clang__)
    __builtin_memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#else
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--)
    {
        *p++ = 0;
    }
#endif
}

/*
 * HQC IND-CCA2 KEM wrappers.
 *
 * The previous wrappers exposed the bare IND-CPA PKE (encrypt-a-seed), which has
 * a non-zero decryption-failure rate and a reachable decryption oracle. These
 * replace them with the vetted NIST KEM API (crypto_kem_keypair/enc/dec from
 * src/common/kem.c). Everything the app does now runs through encapsulate/
 * decapsulate → a 32-byte shared secret, which callers stretch with HKDF.
 *
 * ENTROPY MODEL. The shipped HQC core links NO OS RNG (see hqc_portability.h):
 * its PRNG takes entropy as a parameter (symmetric.h `prng_init`). We drive it
 * explicitly per operation:
 *   • keygen — DETERMINISTIC from the 32-byte identity seed (the app's identity
 *     model derives keypairs from a stored seed). We reproduce the KEM secret-key
 *     layout by hand rather than calling crypto_kem_keypair (which would draw a
 *     fresh seed and change every user's public key). Using the identity seed
 *     directly as the PKE key seed keeps the PUBLIC KEY byte-identical to the
 *     pre-KEM build → no pk churn, stable safety numbers and friend graph.
 *   • encaps — reseed the PRNG with fresh OS entropy so each encapsulation's
 *     (m, salt) are independent and unpredictable.
 *   • decaps — no entropy; the upstream crypto_kem_dec is constant-time with a
 *     masked implicit-rejection branch (this is the CCA2 property; there is no
 *     decryption oracle).
 *
 * HYGIENE. Every wrapper returns an int status (0 = OK), writes only into
 * CALLER-allocated buffers (no malloc here → no cross-module free on the TS/Swift
 * side), and the decode path is the constant-time crypto_kem_dec.
 *
 * KEM secret-key layout (must match crypto_kem_keypair's serialization exactly):
 *   sk = ek_pke[PUBLIC_KEY_BYTES] || dk_pke[SEED_BYTES]
 *        || sigma[PARAM_SECURITY_BYTES] || seed_kem[SEED_BYTES]
 * crypto_kem_dec reads ek_pke, dk_pke and sigma; the trailing seed_kem is stored
 * for format-compatibility and is unused in decapsulation. sigma feeds only the
 * implicit-rejection (invalid-ciphertext) branch, so any secret deterministic
 * value is cryptographically sound — we derive sigma/seed_kem from the identity
 * seed via a domain-separated SHAKE-256 XOF so the whole keypair is reproducible.
 */

/* ---------- WRAPPER: deterministic KEM keypair from a 32-byte identity seed ---------- */

int hqc_kem_keypair_wrap(const uint8_t seed[SEED_BYTES],
                         uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                         uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
    uint8_t ek_pke[PUBLIC_KEY_BYTES];
    uint8_t dk_pke[SEED_BYTES];
    uint8_t seed_pke[SEED_BYTES];
    uint8_t derived[2 * PARAM_SECURITY_BYTES]; /* sigma || seed_kem */

    /* PKE keygen is deterministic in the seed → the public key is stable across
       the PKE→KEM migration for a given identity seed. hqc_pke_keygen mutates its
       seed argument, so hand it a private copy. */
    memcpy(seed_pke, seed, SEED_BYTES);
    hqc_pke_keygen(ek_pke, dk_pke, seed_pke);

    /* sigma || seed_kem — domain-separated deterministic bytes from the seed. */
    {
        uint8_t din[SEED_BYTES + 12];
        shake256_xof_ctx ctx;
        memcpy(din, seed, SEED_BYTES);
        memcpy(din + SEED_BYTES, "hqc-kem-sk\0\0", 12); /* domain separation tag */
        xof_init(&ctx, din, (uint32_t)sizeof din);
        xof_get_bytes(&ctx, derived, (uint32_t)sizeof derived);
        secure_memzero(din, sizeof din);
    }

    memcpy(pk, ek_pke, PUBLIC_KEY_BYTES);
    memcpy(sk, ek_pke, PUBLIC_KEY_BYTES);
    memcpy(sk + PUBLIC_KEY_BYTES, dk_pke, SEED_BYTES);
    memcpy(sk + PUBLIC_KEY_BYTES + SEED_BYTES, derived, PARAM_SECURITY_BYTES);
    memcpy(sk + PUBLIC_KEY_BYTES + SEED_BYTES + PARAM_SECURITY_BYTES,
           derived + PARAM_SECURITY_BYTES, SEED_BYTES);

    secure_memzero(dk_pke, sizeof dk_pke);
    secure_memzero(seed_pke, sizeof seed_pke);
    secure_memzero(derived, sizeof derived);
    return 0;
}

/* ---------- WRAPPER: encapsulate to a public key (fresh OS entropy) ---------- */

int hqc_kem_enc_wrap(uint8_t ct[CRYPTO_CIPHERTEXTBYTES],
                     uint8_t ss[CRYPTO_BYTES],
                     const uint8_t pk[CRYPTO_PUBLICKEYBYTES])
{
    /* crypto_kem_enc draws m(PARAM_SECURITY_BYTES) + salt(SALT_BYTES) from the
       PRNG. Reseed it with fresh OS entropy so every encapsulation is independent.
       NOTE: the PRNG is process-global state — callers must not run keygen/encaps
       concurrently on the same process without external serialization. */
    uint8_t entropy[PARAM_SECURITY_BYTES + SALT_BYTES];
    hqc_getrandom(entropy, sizeof entropy);
    prng_init(entropy, NULL, (uint32_t)sizeof entropy, 0);
    int rc = crypto_kem_enc(ct, ss, pk);
    secure_memzero(entropy, sizeof entropy);
    return rc;
}

/* ---------- WRAPPER: decapsulate (constant-time; no entropy) ---------- */

int hqc_kem_dec_wrap(uint8_t ss[CRYPTO_BYTES],
                     const uint8_t ct[CRYPTO_CIPHERTEXTBYTES],
                     const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
    return crypto_kem_dec(ss, ct, sk);
}
