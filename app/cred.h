#ifndef __CRED_H__
#define __CRED_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cbor.h"

#define COSE_ALG_ES256  (-7)
#define COSE_ALG_EDDSA  (-8)
#define COSE_ALG_ECDH   (-25) /* ECDH-ES + HKDF-256, CTAP2 key agreement */

/*
 * Credential ID / U2F key handle, private key is derived from it - nothing is stored for
 * non-discoverable credentials:
 *   [0]      version
 *   [1]      flags
 *   [2..33]  random nonce
 *   [34..49] HMAC(mac key, [0..33] | rpIdHash) truncated
 */
#define CRED_ID_LEN     50
#define CRED_NONCE_LEN  32
#define CRED_TAG_LEN    16

#define CRED_FLAG_PROTECT_MASK 0x03 /* credProtect level 0..3, 0 = not requested */
#define CRED_FLAG_EDDSA        0x04
#define CRED_FLAG_RK           0x08
#define CRED_FLAG_HMAC_SECRET  0x10

#define CRED_SIG_MAX 72 /* DER ECDSA P-256 */

typedef struct
{
    uint8_t id[CRED_ID_LEN];
    uint8_t flags;
    uint8_t priv[32];
    uint8_t pub[64]; /* P-256 x | y, Ed25519 uses the first 32 bytes */
    bool pub_valid;
} cred_t;

void cred_init(void);

/* master secret changes (first boot, reset) */
void cred_set_master(const uint8_t master[32]);

bool cred_create(cred_t *c, const uint8_t rp_id_hash[32], uint8_t flags);
bool cred_load(cred_t *c, const uint8_t *id, size_t id_len, const uint8_t rp_id_hash[32]);
void cred_wipe(cred_t *c);

int32_t cred_alg(const cred_t *c);
uint8_t cred_protect(const cred_t *c);
const uint8_t *cred_pubkey(cred_t *c);

/* signs msg (ES256: DER signature of SHA-256(msg), EdDSA: raw 64 bytes), returns length or 0 */
size_t cred_sign(cred_t *c, const uint8_t *msg, size_t len, uint8_t sig[CRED_SIG_MAX]);
void cred_put_cose_key(cbor_writer_t *w, cred_t *c);

/* hmac-secret CredRandom */
void cred_hmac_secret_key(const cred_t *c, bool uv, uint8_t out[32]);

/* device attestation key (U2F batch certificate), P-256 */
void cred_attest_key(uint8_t priv[32], uint8_t pub[64]);

/* P-256 helpers */
size_t ecdsa_sign_der(const uint8_t priv[32], const uint8_t hash[32], uint8_t sig[CRED_SIG_MAX]);
bool p256_keygen(uint8_t priv[32], uint8_t pub[64]);
bool p256_ecdh(const uint8_t priv[32], const uint8_t peer_pub[64], uint8_t z[32]);

#ifdef __cplusplus
}
#endif
#endif /* __CRED_H__ */
