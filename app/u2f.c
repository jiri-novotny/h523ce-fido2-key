#include <stdbool.h>
#include <string.h>

#include CMSIS_device_header
#include "monocypher.h"

#include "cred.h"
#include "sha256.h"
#include "store.h"
#include "up.h"

#include "u2f.h"

/* FIDO U2F Raw Message Formats v1.2 */

#define U2F_REGISTER     0x01
#define U2F_AUTHENTICATE 0x02
#define U2F_VERSION      0x03

#define AUTH_CHECK_ONLY  0x07
#define AUTH_ENFORCE_UP  0x03
#define AUTH_DONT_UP     0x08

#define SW_NO_ERROR           0x9000
#define SW_CONDITIONS_NOT_SAT 0x6985
#define SW_WRONG_DATA         0x6a80
#define SW_WRONG_LENGTH       0x6700
#define SW_INS_NOT_SUPPORTED  0x6d00
#define SW_CLA_NOT_SUPPORTED  0x6e00

/* browsers poll every few hundred ms while the user is asked to touch */
#define UP_POLL_TIMEOUT_MS 2000

#define CERT_MAX 400

static uint8_t cert[CERT_MAX];
static size_t cert_len = 0;

static bool up_waiting = false;
static bool up_declined = false;
static uint32_t up_poll_tick = 0;
static uint32_t up_start_count = 0;
static uint32_t up_start_next = 0;

/* DER: tag + length header for content of len bytes, returns header length */
static size_t der_hdr(uint8_t *out, uint8_t tag, size_t len)
{
    out[0] = tag;
    if (len < 0x80)
    {
        out[1] = (uint8_t)len;
        return 2;
    }
    if (len <= 0xff)
    {
        out[1] = 0x81;
        out[2] = (uint8_t)len;
        return 3;
    }
    out[1] = 0x82;
    out[2] = (uint8_t)(len >> 8);
    out[3] = (uint8_t)len;
    return 4;
}

/* wrap buf[0..len) in tag, in place; buf must have 4 spare bytes */
static size_t der_wrap(uint8_t *buf, size_t len, uint8_t tag)
{
    uint8_t hdr[4];
    size_t n = der_hdr(hdr, tag, len);

    memmove(&buf[n], buf, len);
    memcpy(buf, hdr, n);
    return n + len;
}

static size_t der_put(uint8_t *out, uint8_t tag, const void *data, size_t len)
{
    size_t n = der_hdr(out, tag, len);
    memcpy(&out[n], data, len);
    return n + len;
}

/* self-signed X.509 v3 certificate for the device attestation key */
static void build_cert(void)
{
    static const uint8_t version[] = {0xa0, 0x03, 0x02, 0x01, 0x02};
    static const uint8_t ecdsa_sha256[] = {0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
    static const uint8_t ec_p256[] = {0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                                      0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    static const uint8_t oid_cn[] = {0x06, 0x03, 0x55, 0x04, 0x03};
    static const char cn[] = "STM32H523 FIDO2 Attestation";
    static const char not_before[] = "250101000000Z";
    static const char not_after[] = "99991231235959Z";

    uint8_t priv[32], pub[64], hash[32], sig[CRED_SIG_MAX];
    uint8_t name[64], validity[40], spki[96], serial[8];
    size_t name_len, validity_len, spki_len, n, sig_len;
    uint8_t *p = cert;

    cred_attest_key(priv, pub);

    /* Name: SEQUENCE { SET { SEQUENCE { CN, UTF8String } } } */
    memcpy(name, oid_cn, sizeof(oid_cn));
    name_len = sizeof(oid_cn);
    name_len += der_put(&name[name_len], 0x0c, cn, sizeof(cn) - 1);
    name_len = der_wrap(name, name_len, 0x30);
    name_len = der_wrap(name, name_len, 0x31);
    name_len = der_wrap(name, name_len, 0x30);

    validity_len = der_put(validity, 0x17, not_before, sizeof(not_before) - 1);
    validity_len += der_put(&validity[validity_len], 0x18, not_after, sizeof(not_after) - 1);
    validity_len = der_wrap(validity, validity_len, 0x30);

    memcpy(spki, ec_p256, sizeof(ec_p256));
    spki_len = sizeof(ec_p256);
    spki_len += der_hdr(&spki[spki_len], 0x03, 66);
    spki[spki_len++] = 0x00; /* unused bits */
    spki[spki_len++] = 0x04; /* uncompressed point */
    memcpy(&spki[spki_len], pub, 64);
    spki_len += 64;
    spki_len = der_wrap(spki, spki_len, 0x30);

    /* positive, minimal encoding serial derived from the public key */
    sha256(pub, sizeof(pub), hash);
    memcpy(serial, hash, sizeof(serial));
    serial[0] = (serial[0] & 0x7f) | 0x01;

    /* TBSCertificate */
    n = 0;
    memcpy(&p[n], version, sizeof(version));
    n += sizeof(version);
    n += der_put(&p[n], 0x02, serial, sizeof(serial));
    memcpy(&p[n], ecdsa_sha256, sizeof(ecdsa_sha256));
    n += sizeof(ecdsa_sha256);
    memcpy(&p[n], name, name_len); /* issuer */
    n += name_len;
    memcpy(&p[n], validity, validity_len);
    n += validity_len;
    memcpy(&p[n], name, name_len); /* subject */
    n += name_len;
    memcpy(&p[n], spki, spki_len);
    n += spki_len;
    n = der_wrap(p, n, 0x30);

    sha256(p, n, hash);
    sig_len = ecdsa_sign_der(priv, hash, sig);
    crypto_wipe(priv, sizeof(priv));
    if (sig_len == 0)
    {
        cert_len = 0;
        return;
    }

    memcpy(&p[n], ecdsa_sha256, sizeof(ecdsa_sha256));
    n += sizeof(ecdsa_sha256);
    n += der_hdr(&p[n], 0x03, sig_len + 1);
    p[n++] = 0x00;
    memcpy(&p[n], sig, sig_len);
    n += sig_len;
    cert_len = der_wrap(p, n, 0x30);
}

void u2f_reset(void)
{
    cert_len = 0;
}

/*
 * U2F has no keepalive - report "conditions not satisfied" until OK was pressed.
 * U2F only has a hash of the site, the display can't name it. U2F has no way to decline
 * either: after Next the polls stay unsatisfied, without the prompt, until they stop.
 */
static bool u2f_user_present(const char *action)
{
    uint32_t now = HAL_GetTick();

    if (up_declined)
    {
        up_poll_tick = now;
        return false;
    }
    if (!up_waiting)
    {
        up_prompt_text(action, "U2F: site not shown", NULL);
        up_waiting = true;
        up_start_count = up_press_count();
        up_start_next = up_next_count();
        up_poll_tick = now;
        up_set_waiting(true);
        return false;
    }

    up_poll_tick = now;
    if (up_press_count() != up_start_count)
    {
        up_waiting = false;
        up_set_waiting(false);
        return true;
    }
    return false;
}

void u2f_tick(void)
{
    if (up_waiting && up_next_count() != up_start_next)
    {
        up_waiting = false;
        up_declined = true;
        up_set_waiting(false);
    }
    if ((up_waiting || up_declined) && (HAL_GetTick() - up_poll_tick) > UP_POLL_TIMEOUT_MS)
    {
        up_waiting = false;
        up_declined = false;
        up_set_waiting(false);
    }
}

static size_t sw(uint8_t *resp, size_t n, uint16_t code)
{
    resp[n++] = (uint8_t)(code >> 8);
    resp[n++] = (uint8_t)code;
    return n;
}

static size_t u2f_register(const uint8_t *data, size_t lc, uint8_t *resp, size_t cap)
{
    const uint8_t *chal = data;
    const uint8_t *app = &data[32];
    uint8_t hash[32], sig[CRED_SIG_MAX];
    sha256_ctx_t ctx;
    cred_t c;
    size_t n = 0, sig_len;
    const uint8_t *pub;
    static const uint8_t zero = 0x00, uncompressed = 0x04;
    uint8_t kh_len = CRED_ID_LEN;

    if (lc != 64)
    {
        return sw(resp, 0, SW_WRONG_LENGTH);
    }
    if (!u2f_user_present("Register at"))
    {
        return sw(resp, 0, SW_CONDITIONS_NOT_SAT);
    }
    if (cert_len == 0)
    {
        build_cert();
    }
    if (cert_len == 0 || !cred_create(&c, app, 0) || cap < 1 + 65 + 1 + CRED_ID_LEN + cert_len + CRED_SIG_MAX + 2)
    {
        return sw(resp, 0, SW_WRONG_DATA);
    }
    pub = cred_pubkey(&c);

    resp[n++] = 0x05;
    resp[n++] = 0x04;
    memcpy(&resp[n], pub, 64);
    n += 64;
    resp[n++] = kh_len;
    memcpy(&resp[n], c.id, CRED_ID_LEN);
    n += CRED_ID_LEN;
    memcpy(&resp[n], cert, cert_len);
    n += cert_len;

    sha256_init(&ctx);
    sha256_update(&ctx, &zero, 1);
    sha256_update(&ctx, app, 32);
    sha256_update(&ctx, chal, 32);
    sha256_update(&ctx, c.id, CRED_ID_LEN);
    sha256_update(&ctx, &uncompressed, 1);
    sha256_update(&ctx, pub, 64);
    sha256_final(&ctx, hash);
    cred_wipe(&c);

    {
        uint8_t priv[32], apub[64];
        cred_attest_key(priv, apub);
        sig_len = ecdsa_sign_der(priv, hash, sig);
        crypto_wipe(priv, sizeof(priv));
    }
    if (sig_len == 0)
    {
        return sw(resp, 0, SW_WRONG_DATA);
    }
    memcpy(&resp[n], sig, sig_len);
    n += sig_len;
    return sw(resp, n, SW_NO_ERROR);
}

static size_t u2f_authenticate(uint8_t p1, const uint8_t *data, size_t lc, uint8_t *resp, size_t cap)
{
    const uint8_t *chal = data;
    const uint8_t *app = &data[32];
    uint8_t hash[32], sig[CRED_SIG_MAX], ctr_be[4];
    sha256_ctx_t ctx;
    cred_t c;
    uint8_t flags;
    uint32_t ctr;
    size_t n = 0, sig_len;

    if (lc < 65 || lc != 65U + data[64])
    {
        return sw(resp, 0, SW_WRONG_LENGTH);
    }
    if (!cred_load(&c, &data[65], data[64], app))
    {
        return sw(resp, 0, SW_WRONG_DATA);
    }
    /* U2F signs with ECDSA only and cannot do user verification */
    if (cred_alg(&c) != COSE_ALG_ES256 || cred_protect(&c) == 3 || !store_cred_live(&c))
    {
        cred_wipe(&c);
        return sw(resp, 0, SW_WRONG_DATA);
    }

    if (p1 == AUTH_CHECK_ONLY)
    {
        cred_wipe(&c);
        return sw(resp, 0, SW_CONDITIONS_NOT_SAT);
    }
    else if (p1 == AUTH_ENFORCE_UP)
    {
        if (!u2f_user_present("Sign in to"))
        {
            cred_wipe(&c);
            return sw(resp, 0, SW_CONDITIONS_NOT_SAT);
        }
        flags = 0x01;
    }
    else if (p1 == AUTH_DONT_UP)
    {
        flags = 0x00;
    }
    else
    {
        cred_wipe(&c);
        return sw(resp, 0, SW_WRONG_DATA);
    }

    ctr = store_counter_next();
    ctr_be[0] = (uint8_t)(ctr >> 24);
    ctr_be[1] = (uint8_t)(ctr >> 16);
    ctr_be[2] = (uint8_t)(ctr >> 8);
    ctr_be[3] = (uint8_t)ctr;

    sha256_init(&ctx);
    sha256_update(&ctx, app, 32);
    sha256_update(&ctx, &flags, 1);
    sha256_update(&ctx, ctr_be, 4);
    sha256_update(&ctx, chal, 32);
    sha256_final(&ctx, hash);
    sig_len = ecdsa_sign_der(c.priv, hash, sig);
    cred_wipe(&c);
    if (sig_len == 0 || cap < 5 + sig_len + 2)
    {
        return sw(resp, 0, SW_WRONG_DATA);
    }

    resp[n++] = flags;
    memcpy(&resp[n], ctr_be, 4);
    n += 4;
    memcpy(&resp[n], sig, sig_len);
    n += sig_len;
    return sw(resp, n, SW_NO_ERROR);
}

size_t u2f_process(const uint8_t *req, size_t len, uint8_t *resp, size_t cap)
{
    const uint8_t *data = NULL;
    size_t lc = 0;

    if (len < 4)
    {
        return sw(resp, 0, SW_WRONG_LENGTH);
    }

    /* ISO 7816-4 APDU, short or extended length encoding */
    if (len > 4)
    {
        if (req[4] == 0 && len >= 7)
        {
            lc = ((size_t)req[5] << 8) | req[6];
            data = &req[7];
            if (len == 7)
            {
                lc = 0; /* only extended Le present */
            }
            else if (len != 7 + lc && len != 9 + lc)
            {
                return sw(resp, 0, SW_WRONG_LENGTH);
            }
        }
        else
        {
            lc = req[4];
            data = &req[5];
            if (len == 5)
            {
                lc = 0; /* only short Le present */
            }
            else if (len != 5 + lc && len != 6 + lc)
            {
                return sw(resp, 0, SW_WRONG_LENGTH);
            }
        }
    }

    if (req[0] != 0x00)
    {
        return sw(resp, 0, SW_CLA_NOT_SUPPORTED);
    }

    switch (req[1])
    {
    case U2F_REGISTER:
        return u2f_register(data, lc, resp, cap);

    case U2F_AUTHENTICATE:
        return u2f_authenticate(req[2], data, lc, resp, cap);

    case U2F_VERSION:
        if (lc != 0)
        {
            return sw(resp, 0, SW_WRONG_LENGTH);
        }
        memcpy(resp, "U2F_V2", 6);
        return sw(resp, 6, SW_NO_ERROR);

    default:
        return sw(resp, 0, SW_INS_NOT_SUPPORTED);
    }
}
