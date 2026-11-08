#include <string.h>

#include "monocypher-ed25519.h"
#include "monocypher.h"
#include "uECC.h"

#include "rng.h"
#include "sha256.h"

#include "cred.h"

#define CRED_VERSION 1

/* P-256 group order, big endian */
static const uint8_t p256_n[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
                                   0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};

/* keys derived from the master secret */
static uint8_t key_mac[32];
static uint8_t key_priv[32];
static uint8_t key_hmac_secret[32];
static uint8_t key_attest[32];

static int uecc_rng(uint8_t *dest, unsigned size)
{
    return rng_read(dest, size) ? 1 : 0;
}

void cred_init(void)
{
    uECC_set_rng(uecc_rng);
}

static void derive(const uint8_t master[32], const char *label, uint8_t out[32])
{
    hmac_sha256(master, 32, label, strlen(label), out);
}

void cred_set_master(const uint8_t master[32])
{
    derive(master, "cred mac", key_mac);
    derive(master, "cred priv", key_priv);
    derive(master, "hmac-secret", key_hmac_secret);
    derive(master, "attestation", key_attest);
}

static bool p256_valid_priv(const uint8_t priv[32])
{
    static const uint8_t zero[32] = {0};
    return memcmp(priv, p256_n, 32) < 0 && memcmp(priv, zero, 32) != 0;
}

/* deterministic P-256 private key from HMAC(key, msg | counter) */
static void derive_p256(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t priv[32])
{
    for (uint8_t ctr = 0;; ctr++)
    {
        hmac_sha256_ctx_t ctx;

        hmac_sha256_init(&ctx, key, 32);
        hmac_sha256_update(&ctx, msg, len);
        hmac_sha256_update(&ctx, &ctr, 1);
        hmac_sha256_final(&ctx, priv);
        if (p256_valid_priv(priv))
        {
            return;
        }
    }
}

static void cred_tag(const uint8_t id[CRED_ID_LEN], const uint8_t rp_id_hash[32], uint8_t tag[32])
{
    hmac_sha256_ctx_t ctx;

    hmac_sha256_init(&ctx, key_mac, sizeof(key_mac));
    hmac_sha256_update(&ctx, id, CRED_ID_LEN - CRED_TAG_LEN);
    hmac_sha256_update(&ctx, rp_id_hash, 32);
    hmac_sha256_final(&ctx, tag);
}

static void cred_derive(cred_t *c, const uint8_t rp_id_hash[32])
{
    uint8_t msg[CRED_ID_LEN - CRED_TAG_LEN + 32];

    memcpy(msg, c->id, CRED_ID_LEN - CRED_TAG_LEN);
    memcpy(&msg[CRED_ID_LEN - CRED_TAG_LEN], rp_id_hash, 32);

    if (c->flags & CRED_FLAG_EDDSA)
    {
        /* any 32 bytes are a valid Ed25519 seed, keep counter byte for a uniform construction */
        hmac_sha256_ctx_t ctx;
        uint8_t ctr = 0;

        hmac_sha256_init(&ctx, key_priv, sizeof(key_priv));
        hmac_sha256_update(&ctx, msg, sizeof(msg));
        hmac_sha256_update(&ctx, &ctr, 1);
        hmac_sha256_final(&ctx, c->priv);
    }
    else
    {
        derive_p256(key_priv, msg, sizeof(msg), c->priv);
    }
    c->pub_valid = false;
    crypto_wipe(msg, sizeof(msg));
}

bool cred_create(cred_t *c, const uint8_t rp_id_hash[32], uint8_t flags)
{
    uint8_t tag[32];

    memset(c, 0, sizeof(*c));
    c->id[0] = CRED_VERSION;
    c->id[1] = flags;
    c->flags = flags;
    if (!rng_read(&c->id[2], CRED_NONCE_LEN))
    {
        return false;
    }
    cred_tag(c->id, rp_id_hash, tag);
    memcpy(&c->id[CRED_ID_LEN - CRED_TAG_LEN], tag, CRED_TAG_LEN);

    cred_derive(c, rp_id_hash);
    return true;
}

bool cred_load(cred_t *c, const uint8_t *id, size_t id_len, const uint8_t rp_id_hash[32])
{
    uint8_t tag[32];

    if (id_len != CRED_ID_LEN || id[0] != CRED_VERSION)
    {
        return false;
    }

    memset(c, 0, sizeof(*c));
    memcpy(c->id, id, CRED_ID_LEN);
    cred_tag(c->id, rp_id_hash, tag);
    if (crypto_verify16(tag, &c->id[CRED_ID_LEN - CRED_TAG_LEN]) != 0)
    {
        return false;
    }

    c->flags = c->id[1];
    cred_derive(c, rp_id_hash);
    return true;
}

void cred_wipe(cred_t *c)
{
    crypto_wipe(c, sizeof(*c));
}

int32_t cred_alg(const cred_t *c)
{
    return (c->flags & CRED_FLAG_EDDSA) ? COSE_ALG_EDDSA : COSE_ALG_ES256;
}

uint8_t cred_protect(const cred_t *c)
{
    return c->flags & CRED_FLAG_PROTECT_MASK;
}

const uint8_t *cred_pubkey(cred_t *c)
{
    if (!c->pub_valid)
    {
        if (c->flags & CRED_FLAG_EDDSA)
        {
            uint8_t sk[64];
            uint8_t seed[32];

            memcpy(seed, c->priv, sizeof(seed));
            crypto_ed25519_key_pair(sk, c->pub, seed);
            crypto_wipe(sk, sizeof(sk));
        }
        else
        {
            uECC_compute_public_key(c->priv, c->pub, uECC_secp256r1());
        }
        c->pub_valid = true;
    }
    return c->pub;
}

/* DER INTEGER from 32 byte big endian unsigned value */
static size_t der_uint(uint8_t *out, const uint8_t *v)
{
    size_t skip = 0;
    size_t n = 0;

    while (skip < 31 && v[skip] == 0)
    {
        skip++;
    }
    out[n++] = 0x02;
    if (v[skip] & 0x80)
    {
        out[n++] = 33 - skip;
        out[n++] = 0x00;
    }
    else
    {
        out[n++] = 32 - skip;
    }
    memcpy(&out[n], &v[skip], 32 - skip);
    return n + 32 - skip;
}

size_t ecdsa_sign_der(const uint8_t priv[32], const uint8_t hash[32], uint8_t sig[CRED_SIG_MAX])
{
    uint8_t rs[64];
    size_t n;

    if (!uECC_sign(priv, hash, 32, rs, uECC_secp256r1()))
    {
        return 0;
    }

    n = 2;
    n += der_uint(&sig[n], rs);
    n += der_uint(&sig[n], &rs[32]);
    sig[0] = 0x30;
    sig[1] = (uint8_t)(n - 2);
    return n;
}

size_t cred_sign(cred_t *c, const uint8_t *msg, size_t len, uint8_t sig[CRED_SIG_MAX])
{
    if (c->flags & CRED_FLAG_EDDSA)
    {
        uint8_t sk[64];
        uint8_t seed[32];

        memcpy(seed, c->priv, sizeof(seed));
        crypto_ed25519_key_pair(sk, c->pub, seed);
        c->pub_valid = true;
        crypto_ed25519_sign(sig, sk, msg, len);
        crypto_wipe(sk, sizeof(sk));
        return 64;
    }
    else
    {
        uint8_t hash[32];

        sha256(msg, len, hash);
        return ecdsa_sign_der(c->priv, hash, sig);
    }
}

void cred_put_cose_key(cbor_writer_t *w, cred_t *c)
{
    const uint8_t *pub = cred_pubkey(c);

    if (c->flags & CRED_FLAG_EDDSA)
    {
        cbor_put_map(w, 4);
        cbor_put_int(w, 1); /* kty: OKP */
        cbor_put_int(w, 1);
        cbor_put_int(w, 3); /* alg */
        cbor_put_int(w, COSE_ALG_EDDSA);
        cbor_put_int(w, -1); /* crv: Ed25519 */
        cbor_put_int(w, 6);
        cbor_put_int(w, -2); /* x */
        cbor_put_bytes(w, pub, 32);
    }
    else
    {
        cbor_put_map(w, 5);
        cbor_put_int(w, 1); /* kty: EC2 */
        cbor_put_int(w, 2);
        cbor_put_int(w, 3); /* alg */
        cbor_put_int(w, COSE_ALG_ES256);
        cbor_put_int(w, -1); /* crv: P-256 */
        cbor_put_int(w, 1);
        cbor_put_int(w, -2); /* x */
        cbor_put_bytes(w, pub, 32);
        cbor_put_int(w, -3); /* y */
        cbor_put_bytes(w, &pub[32], 32);
    }
}

void cred_hmac_secret_key(const cred_t *c, bool uv, uint8_t out[32])
{
    hmac_sha256_ctx_t ctx;
    uint8_t uv_byte = uv ? 1 : 0;

    hmac_sha256_init(&ctx, key_hmac_secret, sizeof(key_hmac_secret));
    hmac_sha256_update(&ctx, c->id, CRED_ID_LEN);
    hmac_sha256_update(&ctx, &uv_byte, 1);
    hmac_sha256_final(&ctx, out);
}

void cred_attest_key(uint8_t priv[32], uint8_t pub[64])
{
    derive_p256(key_attest, (const uint8_t *)"batch", 5, priv);
    uECC_compute_public_key(priv, pub, uECC_secp256r1());
}

bool p256_keygen(uint8_t priv[32], uint8_t pub[64])
{
    return uECC_make_key(pub, priv, uECC_secp256r1()) == 1;
}

bool p256_ecdh(const uint8_t priv[32], const uint8_t peer_pub[64], uint8_t z[32])
{
    if (!uECC_valid_public_key(peer_pub, uECC_secp256r1()))
    {
        return false;
    }
    return uECC_shared_secret(peer_pub, priv, z, uECC_secp256r1()) == 1;
}
