/*
 * Portable OS entropy, force-included into every compiled HQC file. The
 * reference core takes entropy as a parameter, so this is unused today; it
 * gives a future upstream revision a portable hqc_getrandom().
 */
#ifndef HQC_PORTABILITY_H
#define HQC_PORTABILITY_H

#include <stddef.h>
#include <stdint.h>

#if defined(__APPLE__)
#include <stdlib.h> /* arc4random_buf — always available on iOS/macOS */
static inline void hqc_getrandom(void *buf, size_t len) { arc4random_buf(buf, len); }

#elif defined(__linux__)
#include <sys/random.h> /* getrandom(2) */
static inline void hqc_getrandom(void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        long r = (long)getrandom((uint8_t *)buf + off, len - off, 0);
        if (r > 0) off += (size_t)r;
    }
}

#else
#include <stdlib.h>
static inline void hqc_getrandom(void *buf, size_t len) {
    for (size_t i = 0; i < len; i++) ((uint8_t *)buf)[i] = (uint8_t)rand();
}
#endif

#endif /* HQC_PORTABILITY_H */
