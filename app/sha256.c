#include <string.h>

#include "monocypher.h"

#include "sha256.h"

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t state[8], const uint8_t block[SHA256_BLOCK_SIZE])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8) | block[4 * i + 3];
    }
    for (int i = 16; i < 64; i++)
    {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (int i = 0; i < 64; i++)
    {
        uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;

    crypto_wipe(w, sizeof(w));
}

void sha256_init(sha256_ctx_t *ctx)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(ctx->state, iv, sizeof(iv));
    ctx->count = 0;
}

void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len)
{
    const uint8_t *p = data;
    size_t fill = ctx->count % SHA256_BLOCK_SIZE;

    ctx->count += len;

    if (fill)
    {
        size_t n = SHA256_BLOCK_SIZE - fill;
        if (n > len)
        {
            n = len;
        }
        memcpy(&ctx->buf[fill], p, n);
        p += n;
        len -= n;
        if (fill + n < SHA256_BLOCK_SIZE)
        {
            return;
        }
        sha256_block(ctx->state, ctx->buf);
    }

    while (len >= SHA256_BLOCK_SIZE)
    {
        sha256_block(ctx->state, p);
        p += SHA256_BLOCK_SIZE;
        len -= SHA256_BLOCK_SIZE;
    }

    memcpy(ctx->buf, p, len);
}

void sha256_final(sha256_ctx_t *ctx, uint8_t out[SHA256_SIZE])
{
    uint64_t bits = ctx->count * 8;
    size_t fill = ctx->count % SHA256_BLOCK_SIZE;

    ctx->buf[fill++] = 0x80;
    if (fill > SHA256_BLOCK_SIZE - 8)
    {
        memset(&ctx->buf[fill], 0, SHA256_BLOCK_SIZE - fill);
        sha256_block(ctx->state, ctx->buf);
        fill = 0;
    }
    memset(&ctx->buf[fill], 0, SHA256_BLOCK_SIZE - 8 - fill);
    for (int i = 0; i < 8; i++)
    {
        ctx->buf[SHA256_BLOCK_SIZE - 1 - i] = (uint8_t)(bits >> (8 * i));
    }
    sha256_block(ctx->state, ctx->buf);

    for (int i = 0; i < 8; i++)
    {
        out[4 * i] = (uint8_t)(ctx->state[i] >> 24);
        out[4 * i + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[4 * i + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[4 * i + 3] = (uint8_t)ctx->state[i];
    }
    crypto_wipe(ctx, sizeof(*ctx));
}

void sha256(const void *data, size_t len, uint8_t out[SHA256_SIZE])
{
    sha256_ctx_t ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *key, size_t key_len)
{
    uint8_t k[SHA256_BLOCK_SIZE] = {0};

    if (key_len > SHA256_BLOCK_SIZE)
    {
        sha256(key, key_len, k);
    }
    else
    {
        memcpy(k, key, key_len);
    }

    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        ctx->okey[i] = k[i] ^ 0x5c;
        k[i] ^= 0x36;
    }
    sha256_init(&ctx->inner);
    sha256_update(&ctx->inner, k, sizeof(k));
    crypto_wipe(k, sizeof(k));
}

void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const void *data, size_t len)
{
    sha256_update(&ctx->inner, data, len);
}

void hmac_sha256_final(hmac_sha256_ctx_t *ctx, uint8_t out[SHA256_SIZE])
{
    uint8_t ihash[SHA256_SIZE];
    sha256_ctx_t outer;

    sha256_final(&ctx->inner, ihash);
    sha256_init(&outer);
    sha256_update(&outer, ctx->okey, sizeof(ctx->okey));
    sha256_update(&outer, ihash, sizeof(ihash));
    sha256_final(&outer, out);

    crypto_wipe(ihash, sizeof(ihash));
    crypto_wipe(ctx, sizeof(*ctx));
}

void hmac_sha256(const uint8_t *key, size_t key_len, const void *data, size_t len, uint8_t out[SHA256_SIZE])
{
    hmac_sha256_ctx_t ctx;

    hmac_sha256_init(&ctx, key, key_len);
    hmac_sha256_update(&ctx, data, len);
    hmac_sha256_final(&ctx, out);
}

void hkdf_sha256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, const char *info,
                 uint8_t out[SHA256_SIZE])
{
    static const uint8_t one = 0x01;
    uint8_t prk[SHA256_SIZE];
    hmac_sha256_ctx_t ctx;

    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    hmac_sha256_init(&ctx, prk, sizeof(prk));
    hmac_sha256_update(&ctx, info, strlen(info));
    hmac_sha256_update(&ctx, &one, 1);
    hmac_sha256_final(&ctx, out);

    crypto_wipe(prk, sizeof(prk));
}
