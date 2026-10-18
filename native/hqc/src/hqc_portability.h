/*
 * Portable OS entropy, force-included into every compiled HQC file. The
 * reference core takes entropy as a parameter; hqc_kem_enc_wrap (low_wrap.c)
 * draws each encapsulation's entropy from hqc_getrandom(). A platform without
 * an OS generator does not build: there is no fallback, since a predictable
 * encapsulation gives the session key away.
 */
#ifndef HQC_PORTABILITY_H
#define HQC_PORTABILITY_H

#include <stddef.h>
#include <stdint.h>

#if defined(__APPLE__)
#include <stdlib.h> /* arc4random_buf — always available on iOS/macOS */
static inline void hqc_getrandom(void *buf, size_t len) { arc4random_buf(buf, len); }

#elif defined(__linux__) /* Linux and Android (bionic has getrandom from API 28) */
#include <sys/random.h> /* getrandom(2) */
static inline void hqc_getrandom(void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        long r = (long)getrandom((uint8_t *)buf + off, len - off, 0);
        if (r > 0) off += (size_t)r;
    }
}

#elif defined(_WIN32)
#include <stdlib.h>
#include <windows.h>
#include <bcrypt.h> /* BCryptGenRandom; link bcrypt */
static inline void hqc_getrandom(void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ULONG chunk = len > 0x10000000u ? 0x10000000u : (ULONG)len;
        if (BCryptGenRandom(NULL, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) abort();
        p += chunk;
        len -= chunk;
    }
}

#else
#error "hqc_portability.h: no OS entropy source for this platform"
#endif

#endif /* HQC_PORTABILITY_H */
