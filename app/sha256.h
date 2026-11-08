#ifndef __SHA256_H__
#define __SHA256_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

#define SHA256_SIZE       32U
#define SHA256_BLOCK_SIZE 64U

typedef struct
{
    uint32_t state[8];
    uint64_t count; /* bytes */
    uint8_t buf[SHA256_BLOCK_SIZE];
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t out[SHA256_SIZE]);
void sha256(const void *data, size_t len, uint8_t out[SHA256_SIZE]);

typedef struct
{
    sha256_ctx_t inner;
    uint8_t okey[SHA256_BLOCK_SIZE];
} hmac_sha256_ctx_t;

void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *key, size_t key_len);
void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const void *data, size_t len);
void hmac_sha256_final(hmac_sha256_ctx_t *ctx, uint8_t out[SHA256_SIZE]);
void hmac_sha256(const uint8_t *key, size_t key_len, const void *data, size_t len, uint8_t out[SHA256_SIZE]);

/* HKDF-SHA-256 (RFC 5869) with output length of one block (32 bytes) */
void hkdf_sha256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, const char *info,
                 uint8_t out[SHA256_SIZE]);

#ifdef __cplusplus
}
#endif
#endif /* __SHA256_H__ */
