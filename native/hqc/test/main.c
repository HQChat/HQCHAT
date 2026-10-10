/*
 * Checks the HQC KEM wrapper: deterministic keygen from a seed, encapsulation
 * round trips with fresh entropy, and implicit rejection of a tampered
 * ciphertext or the wrong key. Run by the Nix package's check phase.
 */

#include <stdio.h>
#include <string.h>
#include "public_wrapper.h"

static int failures = 0;

static void check(int ok, const char *what) {
    printf(ok ? "  ok   %s\n" : "  FAIL %s\n", what);
    if (!ok) failures++;
}

int main(void) {
    static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    static uint8_t sk[CRYPTO_SECRETKEYBYTES];
    static uint8_t pk2[CRYPTO_PUBLICKEYBYTES];
    static uint8_t sk2[CRYPTO_SECRETKEYBYTES];
    static uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    static uint8_t ct2[CRYPTO_CIPHERTEXTBYTES];
    static uint8_t ss[CRYPTO_BYTES];
    static uint8_t ss2[CRYPTO_BYTES];
    static uint8_t ssDec[CRYPTO_BYTES];

    uint8_t seed[SEED_BYTES];
    uint8_t otherSeed[SEED_BYTES];
    memset(seed, 'A', SEED_BYTES);
    memset(otherSeed, 'B', SEED_BYTES);

    printf("HQC KEM wrapper (HQC-256)\n\n");

    printf("Keygen\n");
    check(hqc_kem_keypair_wrap(seed, pk, sk) == 0, "keypair from a 32-byte seed returns 0");

    /* Deterministic in the seed: identities are derived from a stored seed. */
    check(hqc_kem_keypair_wrap(seed, pk2, sk2) == 0, "the same seed keygens again");
    check(memcmp(pk, pk2, sizeof(pk)) == 0, "the same seed yields the same public key");
    check(memcmp(sk, sk2, sizeof(sk)) == 0, "the same seed yields the same secret key");

    check(hqc_kem_keypair_wrap(otherSeed, pk2, sk2) == 0, "a different seed keygens");
    check(memcmp(pk, pk2, sizeof(pk)) != 0, "a different seed yields a different public key");

    printf("\nEncapsulate / decapsulate\n");
    check(hqc_kem_enc_wrap(ct, ss, pk) == 0, "encapsulate returns 0");
    check(hqc_kem_dec_wrap(ssDec, ct, sk) == 0, "decapsulate returns 0");
    check(memcmp(ss, ssDec, CRYPTO_BYTES) == 0, "decapsulate recovers the encapsulated secret");

    /* Fresh OS entropy per call, not derived from the key. */
    check(hqc_kem_enc_wrap(ct2, ss2, pk) == 0, "encapsulate again");
    check(memcmp(ct, ct2, sizeof(ct)) != 0, "each encapsulation produces a different ciphertext");
    check(memcmp(ss, ss2, CRYPTO_BYTES) != 0, "each encapsulation produces a different secret");

    printf("\nImplicit rejection (IND-CCA2)\n");

    /* A tampered ciphertext yields a pseudo-random secret and returns 0, so
     * there is no decryption oracle. */
    ct[0] ^= 0xff;
    check(hqc_kem_dec_wrap(ssDec, ct, sk) == 0,
          "a tampered ciphertext still returns 0 (no oracle)");
    check(memcmp(ss, ssDec, CRYPTO_BYTES) != 0,
          "a tampered ciphertext does not recover the real secret");
    ct[0] ^= 0xff;

    /* The wrong secret key must not open it either. */
    check(hqc_kem_keypair_wrap(otherSeed, pk2, sk2) == 0, "a second keypair for the wrong-key case");
    check(hqc_kem_dec_wrap(ssDec, ct, sk2) == 0, "decapsulating with the wrong key returns 0");
    check(memcmp(ss, ssDec, CRYPTO_BYTES) != 0,
          "the wrong secret key does not recover the secret");

    printf("\n");
    if (failures > 0) {
        printf("%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
