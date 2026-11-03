#ifndef KIOSK_MIC_SHA256_H
#define KIOSK_MIC_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bits;
    unsigned char block[64];
    size_t used;
} sha256_context;

void sha256_init(sha256_context *ctx);
void sha256_update(sha256_context *ctx, const void *data, size_t length);
void sha256_final(sha256_context *ctx, unsigned char out[32]);

#endif
