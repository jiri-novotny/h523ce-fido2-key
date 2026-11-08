#include <stdbool.h>
#include <string.h>

#include CMSIS_device_header
#include "monocypher.h"

#include "aes.h"
#include "cbor.h"
#include "cred.h"
#include "ctaphid.h"
#include "display.h"
#include "rng.h"
#include "sha256.h"
#include "store.h"
#include "u2f.h"
#include "up.h"

#include "ctap2.h"

/* FIDO Client to Authenticator Protocol (CTAP) 2.1 */

#define CMD_MAKE_CREDENTIAL    0x01
#define CMD_GET_ASSERTION      0x02
#define CMD_GET_INFO           0x04
#define CMD_CLIENT_PIN         0x06
#define CMD_RESET              0x07
#define CMD_GET_NEXT_ASSERTION 0x08
#define CMD_CRED_MGMT          0x0a
#define CMD_SELECTION          0x0b

#define CTAP2_OK                         0x00
#define CTAP1_ERR_INVALID_COMMAND        0x01
#define CTAP1_ERR_INVALID_PARAMETER      0x02
#define CTAP1_ERR_INVALID_LENGTH         0x03
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE   0x11
#define CTAP2_ERR_INVALID_CBOR           0x12
#define CTAP2_ERR_MISSING_PARAMETER      0x14
#define CTAP2_ERR_CREDENTIAL_EXCLUDED    0x19
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM  0x26
#define CTAP2_ERR_OPERATION_DENIED       0x27
#define CTAP2_ERR_KEY_STORE_FULL         0x28
#define CTAP2_ERR_UNSUPPORTED_OPTION     0x2b
#define CTAP2_ERR_INVALID_OPTION         0x2c
#define CTAP2_ERR_KEEPALIVE_CANCEL       0x2d
#define CTAP2_ERR_NO_CREDENTIALS         0x2e
#define CTAP2_ERR_USER_ACTION_TIMEOUT    0x2f
#define CTAP2_ERR_NOT_ALLOWED            0x30
#define CTAP2_ERR_PIN_INVALID            0x31
#define CTAP2_ERR_PIN_BLOCKED            0x32
#define CTAP2_ERR_PIN_AUTH_INVALID       0x33
#define CTAP2_ERR_PIN_AUTH_BLOCKED       0x34
#define CTAP2_ERR_PIN_NOT_SET            0x35
#define CTAP2_ERR_PUAT_REQUIRED          0x36
#define CTAP2_ERR_PIN_POLICY_VIOLATION   0x37
#define CTAP2_ERR_INVALID_SUBCOMMAND     0x3e
#define CTAP2_ERR_UNAUTHORIZED_PERMISSION 0x40
#define CTAP1_ERR_OTHER                  0x7f

#define AD_FLAG_UP 0x01
#define AD_FLAG_UV 0x04
#define AD_FLAG_AT 0x40
#define AD_FLAG_ED 0x80

#define PERM_MC  0x01
#define PERM_GA  0x02
#define PERM_CM  0x04
#define PERM_BE  0x08
#define PERM_LBW 0x10
#define PERM_ACFG 0x20

#define UP_TIMEOUT_MS        30000
#define RESET_WINDOW_MS      10000
#define TOKEN_LIFETIME_MS    (10U * 60U * 1000U)
#define NEXT_ASSERTION_MS    30000
#define PIN_MAX_CONSECUTIVE  3
#define MAX_PARAMS           16
#define AUTH_DATA_MAX        512

#define CHECK(x)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        uint8_t _st = (x);                                                                                             \
        if (_st != CTAP2_OK)                                                                                           \
        {                                                                                                              \
            return _st;                                                                                                \
        }                                                                                                              \
    } while (0)

/* AAGUID of this authenticator model */
static const uint8_t aaguid[16] = {0x9b, 0x3e, 0x1f, 0x5a, 0x6c, 0x2d, 0x4e, 0x87,
                                   0xa1, 0x0b, 0x52, 0x23, 0xc8, 0x7f, 0x41, 0xd6};

typedef struct
{
    const uint8_t *p;
    size_t len;
    bool present;
} slice_t;

typedef struct
{
    uint8_t hmac_key[32];
    uint8_t aes_key[32];
} shared_t;

/* pinUvAuthProtocol state, lost on power cycle */
static struct
{
    bool ka_valid;
    uint8_t ka_priv[32];
    uint8_t ka_pub[64];
    uint8_t token[32];
    bool token_valid;
    uint32_t token_tick;
    uint8_t permissions;
    bool rp_bound;
    uint8_t rp_id_hash[32];
    uint8_t consecutive_fails;
} pin;

/* getAssertion state for getNextAssertion */
static struct
{
    bool valid;
    uint32_t tick;
    uint8_t rp_id_hash[32];
    uint8_t cdh[32];
    bool up;
    bool uv;
    bool from_rk;
    bool selected; /* account picked on the display */
    const uint8_t *rp_id;
    size_t rp_id_len;
    uint8_t count;
    uint8_t idx;
    uint8_t cred_id[CRED_ID_LEN]; /* allowList match */
    store_key_t keys[STORE_RK_MAX];
    uint32_t created[STORE_RK_MAX];
    /* hmac-secret */
    bool hmac;
    uint8_t hmac_proto;
    shared_t hmac_shared;
    uint8_t salt[64];
    uint8_t salt_len;
} ga;

/* credentialManagement enumeration state */
static struct
{
    bool rp_valid;
    uint8_t rp_count;
    uint8_t rp_idx;
    uint8_t rp_hash[STORE_RK_MAX][32];
    store_key_t rp_key[STORE_RK_MAX];
    bool cred_valid;
    uint8_t cred_count;
    uint8_t cred_idx;
    store_key_t cred_key[STORE_RK_MAX];
} cm;

static uint8_t auth_data[AUTH_DATA_MAX + 32];
static store_rk_t rk_buf;

/* ------------------------------------------------------------------------- */
/* request parsing helpers                                                   */
/* ------------------------------------------------------------------------- */

static uint8_t parse_params(const uint8_t *req, size_t len, slice_t *params, size_t max)
{
    cbor_reader_t r;
    cbor_item_t m, k, v;

    memset(params, 0, max * sizeof(*params));
    if (len == 0)
    {
        return CTAP2_OK; /* parameters are optional for some commands */
    }

    cbor_reader_init(&r, req, len);
    if (!cbor_read(&r, &m))
    {
        return CTAP2_ERR_INVALID_CBOR;
    }
    if (m.type != CBOR_MAP)
    {
        return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }

    for (uint64_t i = 0; i < m.val; i++)
    {
        if (!cbor_read(&r, &k))
        {
            return CTAP2_ERR_INVALID_CBOR;
        }
        if (k.type != CBOR_UINT)
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (!cbor_read(&r, &v) || !cbor_skip_rest(&r, &v))
        {
            return CTAP2_ERR_INVALID_CBOR;
        }
        if (k.val < max)
        {
            if (params[k.val].present)
            {
                return CTAP2_ERR_INVALID_CBOR;
            }
            params[k.val].p = v.start;
            params[k.val].len = (size_t)(r.p - v.start);
            params[k.val].present = true;
        }
    }
    return CTAP2_OK;
}

static uint8_t slice_read(const slice_t *s, cbor_reader_t *r, cbor_item_t *it, uint8_t type)
{
    cbor_reader_init(r, s->p, s->len);
    if (!cbor_read(r, it))
    {
        return CTAP2_ERR_INVALID_CBOR;
    }
    if (it->type != type)
    {
        return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    return CTAP2_OK;
}

static uint8_t get_bytes(const slice_t *s, const uint8_t **p, size_t *len)
{
    cbor_reader_t r;
    cbor_item_t it;

    CHECK(slice_read(s, &r, &it, CBOR_BYTES));
    *p = it.ptr;
    *len = (size_t)it.val;
    return CTAP2_OK;
}

static uint8_t get_text(const slice_t *s, const uint8_t **p, size_t *len)
{
    cbor_reader_t r;
    cbor_item_t it;

    CHECK(slice_read(s, &r, &it, CBOR_TEXT));
    *p = it.ptr;
    *len = (size_t)it.val;
    return CTAP2_OK;
}

static uint8_t get_uint(const slice_t *s, uint64_t *val)
{
    cbor_reader_t r;
    cbor_item_t it;

    CHECK(slice_read(s, &r, &it, CBOR_UINT));
    *val = it.val;
    return CTAP2_OK;
}

/* iterate a map with text keys, cb gets key and value header (value children not consumed) */
typedef uint8_t (*map_cb_t)(const cbor_item_t *key, const cbor_item_t *val, cbor_reader_t *r, void *ctx);

static uint8_t text_map_foreach(const uint8_t *p, size_t len, map_cb_t cb, void *ctx)
{
    cbor_reader_t r;
    cbor_item_t m, k, v;

    cbor_reader_init(&r, p, len);
    if (!cbor_read(&r, &m))
    {
        return CTAP2_ERR_INVALID_CBOR;
    }
    if (m.type != CBOR_MAP)
    {
        return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }
    for (uint64_t i = 0; i < m.val; i++)
    {
        const uint8_t *child_start;

        if (!cbor_read(&r, &k) || !cbor_skip_rest(&r, &k) || !cbor_read(&r, &v))
        {
            return CTAP2_ERR_INVALID_CBOR;
        }
        child_start = r.p;
        if (k.type == CBOR_TEXT)
        {
            CHECK(cb(&k, &v, &r, ctx));
        }
        /* skip whatever the callback did not consume */
        if (r.p == child_start && !cbor_skip_rest(&r, &v))
        {
            return CTAP2_ERR_INVALID_CBOR;
        }
    }
    return CTAP2_OK;
}

/* iterate an array, cb gets the encoded element */
typedef uint8_t (*array_cb_t)(const uint8_t *p, size_t len, void *ctx);

static uint8_t array_foreach(const slice_t *s, array_cb_t cb, void *ctx)
{
    cbor_reader_t r;
    cbor_item_t a, e;

    CHECK(slice_read(s, &r, &a, CBOR_ARRAY));
    for (uint64_t i = 0; i < a.val; i++)
    {
        if (!cbor_read(&r, &e) || !cbor_skip_rest(&r, &e))
        {
            return CTAP2_ERR_INVALID_CBOR;
        }
        CHECK(cb(e.start, (size_t)(r.p - e.start), ctx));
    }
    return CTAP2_OK;
}

static uint8_t array_count(const slice_t *s, size_t *count)
{
    cbor_reader_t r;
    cbor_item_t a;

    CHECK(slice_read(s, &r, &a, CBOR_ARRAY));
    *count = (size_t)a.val;
    return CTAP2_OK;
}

/* PublicKeyCredentialDescriptor */
typedef struct
{
    const uint8_t *id;
    size_t id_len;
    bool public_key;
} descriptor_t;

static uint8_t descriptor_cb(const cbor_item_t *k, const cbor_item_t *v, cbor_reader_t *r, void *ctx)
{
    descriptor_t *d = ctx;

    if (cbor_text_eq(k, "id"))
    {
        if (v->type != CBOR_BYTES)
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        d->id = v->ptr;
        d->id_len = (size_t)v->val;
    }
    else if (cbor_text_eq(k, "type"))
    {
        if (v->type != CBOR_TEXT)
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        d->public_key = cbor_text_eq(v, "public-key");
    }
    return CTAP2_OK;
}

static uint8_t parse_descriptor(const uint8_t *p, size_t len, descriptor_t *d)
{
    memset(d, 0, sizeof(*d));
    CHECK(text_map_foreach(p, len, descriptor_cb, d));
    if (d->id == NULL)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    return CTAP2_OK;
}

/* PublicKeyCredentialUserEntity */
typedef struct
{
    const uint8_t *id;
    size_t id_len;
    const uint8_t *name;
    size_t name_len;
    const uint8_t *display_name;
    size_t display_name_len;
} user_t;

/* account name for the display: name, else displayName */
static const uint8_t *user_shown(const user_t *u)
{
    return u->name_len ? u->name : u->display_name;
}

static size_t user_shown_len(const user_t *u)
{
    return u->name_len ? u->name_len : u->display_name_len;
}

static uint8_t user_cb(const cbor_item_t *k, const cbor_item_t *v, cbor_reader_t *r, void *ctx)
{
    user_t *u = ctx;

    if (cbor_text_eq(k, "id"))
    {
        if (v->type != CBOR_BYTES)
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        u->id = v->ptr;
        u->id_len = (size_t)v->val;
    }
    else if (cbor_text_eq(k, "name") || cbor_text_eq(k, "displayName") || cbor_text_eq(k, "icon"))
    {
        if (v->type != CBOR_TEXT)
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (cbor_text_eq(k, "name"))
        {
            u->name = v->ptr;
            u->name_len = (size_t)v->val;
        }
        else if (cbor_text_eq(k, "displayName"))
        {
            u->display_name = v->ptr;
            u->display_name_len = (size_t)v->val;
        }
    }
    return CTAP2_OK;
}

static uint8_t parse_user(const slice_t *s, user_t *u)
{
    memset(u, 0, sizeof(*u));
    CHECK(text_map_foreach(s->p, s->len, user_cb, u));
    if (u->id == NULL)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (u->id_len > STORE_USER_ID_MAX)
    {
        return CTAP1_ERR_INVALID_LENGTH;
    }
    return CTAP2_OK;
}

/* options map: rk, up, uv; -1 = absent */
typedef struct
{
    int rk;
    int up;
    int uv;
} options_t;

static uint8_t options_cb(const cbor_item_t *k, const cbor_item_t *v, cbor_reader_t *r, void *ctx)
{
    options_t *o = ctx;
    int *dst = NULL;

    if (cbor_text_eq(k, "rk"))
    {
        dst = &o->rk;
    }
    else if (cbor_text_eq(k, "up"))
    {
        dst = &o->up;
    }
    else if (cbor_text_eq(k, "uv"))
    {
        dst = &o->uv;
    }
    if (dst)
    {
        if (!cbor_is_bool(v))
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        *dst = (v->val == CBOR_TRUE) ? 1 : 0;
    }
    return CTAP2_OK;
}

static uint8_t parse_options(const slice_t *s, options_t *o)
{
    o->rk = o->up = o->uv = -1;
    if (!s->present)
    {
        return CTAP2_OK;
    }
    return text_map_foreach(s->p, s->len, options_cb, o);
}

/* copy string truncated to max bytes at an UTF-8 character boundary */
static uint8_t copy_utf8(char *dst, size_t max, const uint8_t *src, size_t len)
{
    if (len > max)
    {
        len = max;
        while (len > 0 && (src[len] & 0xc0) == 0x80)
        {
            len--;
        }
    }
    if (len)
    {
        memcpy(dst, src, len);
    }
    return (uint8_t)len;
}

/* ------------------------------------------------------------------------- */
/* user presence                                                             */
/* ------------------------------------------------------------------------- */

/*
 * Waits for OK with keepalives, Next declines. With a list, show(i) puts item i on the display
 * and Next steps through the items and then a cancel entry (i == count), OK picks one.
 */
static uint8_t wait_choice(uint8_t count, void (*show)(uint8_t), uint8_t *choice)
{
    uint32_t start = HAL_GetTick();
    uint32_t ok = up_press_count();
    uint32_t next = up_next_count();
    uint8_t i = 0;
    uint8_t ret;

    if (show)
    {
        show(0);
    }
    up_set_waiting(true);
    for (;;)
    {
        if (ctaphid_poll(CTAPHID_STATUS_UPNEEDED))
        {
            ret = CTAP2_ERR_KEEPALIVE_CANCEL;
            break;
        }
        if (up_press_count() != ok)
        {
            ret = (show && i == count) ? CTAP2_ERR_OPERATION_DENIED : CTAP2_OK;
            break;
        }
        if (up_next_count() != next)
        {
            if (!show)
            {
                ret = CTAP2_ERR_OPERATION_DENIED;
                break;
            }
            next = up_next_count();
            i = (uint8_t)((i + 1U) % (count + 1U));
            show(i);
            start = HAL_GetTick();
        }
        if ((HAL_GetTick() - start) > UP_TIMEOUT_MS)
        {
            ret = CTAP2_ERR_USER_ACTION_TIMEOUT;
            break;
        }
    }
    up_set_waiting(false);
    if (choice)
    {
        *choice = i;
    }
    return ret;
}

uint8_t ctap2_wait_up(void)
{
    return wait_choice(0, NULL, NULL);
}

/* ------------------------------------------------------------------------- */
/* PIN/UV auth protocols 1 and 2                                             */
/* ------------------------------------------------------------------------- */

static void pin_new_key_agreement(void)
{
    pin.ka_valid = p256_keygen(pin.ka_priv, pin.ka_pub);
}

static void pin_new_token(void)
{
    rng_read(pin.token, sizeof(pin.token));
    pin.token_valid = false;
    pin.permissions = 0;
    pin.rp_bound = false;
}

static bool proto_valid(uint64_t proto)
{
    return proto == 1 || proto == 2;
}

static uint8_t parse_cose_key(const slice_t *s, uint8_t pub[64])
{
    cbor_reader_t r;
    cbor_item_t m, k, v;
    bool have_x = false, have_y = false;

    CHECK(slice_read(s, &r, &m, CBOR_MAP));
    for (uint64_t i = 0; i < m.val; i++)
    {
        if (!cbor_read(&r, &k) || !cbor_skip_rest(&r, &k) || !cbor_read(&r, &v))
        {
            return CTAP2_ERR_INVALID_CBOR;
        }
        if (!cbor_is_int(&k))
        {
            if (!cbor_skip_rest(&r, &v))
            {
                return CTAP2_ERR_INVALID_CBOR;
            }
            continue;
        }
        switch (cbor_int(&k))
        {
        case 1: /* kty EC2 */
            if (!cbor_is_int(&v) || cbor_int(&v) != 2)
            {
                return CTAP1_ERR_INVALID_PARAMETER;
            }
            break;
        case -1: /* crv P-256 */
            if (!cbor_is_int(&v) || cbor_int(&v) != 1)
            {
                return CTAP1_ERR_INVALID_PARAMETER;
            }
            break;
        case -2:
        case -3:
            if (v.type != CBOR_BYTES || v.val != 32)
            {
                return CTAP1_ERR_INVALID_PARAMETER;
            }
            memcpy(cbor_int(&k) == -2 ? pub : &pub[32], v.ptr, 32);
            if (cbor_int(&k) == -2)
            {
                have_x = true;
            }
            else
            {
                have_y = true;
            }
            break;
        default:
            if (!cbor_skip_rest(&r, &v))
            {
                return CTAP2_ERR_INVALID_CBOR;
            }
            break;
        }
    }
    return (have_x && have_y) ? CTAP2_OK : CTAP2_ERR_MISSING_PARAMETER;
}

static uint8_t pin_decapsulate(uint8_t proto, const slice_t *cose, shared_t *sh)
{
    static const uint8_t zero_salt[32] = {0};
    uint8_t peer[64], z[32];

    CHECK(parse_cose_key(cose, peer));
    if (!pin.ka_valid)
    {
        pin_new_key_agreement();
    }
    if (!pin.ka_valid || !p256_ecdh(pin.ka_priv, peer, z))
    {
        return CTAP1_ERR_INVALID_PARAMETER;
    }

    if (proto == 1)
    {
        sha256(z, sizeof(z), sh->hmac_key);
        memcpy(sh->aes_key, sh->hmac_key, 32);
    }
    else
    {
        hkdf_sha256(zero_salt, sizeof(zero_salt), z, sizeof(z), "CTAP2 HMAC key", sh->hmac_key);
        hkdf_sha256(zero_salt, sizeof(zero_salt), z, sizeof(z), "CTAP2 AES key", sh->aes_key);
    }
    crypto_wipe(z, sizeof(z));
    return CTAP2_OK;
}

static size_t pin_encrypt(uint8_t proto, const shared_t *sh, const uint8_t *in, size_t len, uint8_t *out)
{
    static const uint8_t zero_iv[AES_BLOCK_SIZE] = {0};

    if (proto == 1)
    {
        aes256_cbc_encrypt(sh->aes_key, zero_iv, in, out, len);
        return len;
    }
    rng_read(out, AES_BLOCK_SIZE);
    aes256_cbc_encrypt(sh->aes_key, out, in, &out[AES_BLOCK_SIZE], len);
    return len + AES_BLOCK_SIZE;
}

/* out holds out_cap bytes; protocol 1 has no IV, so the plaintext is as long as the input */
static bool pin_decrypt(uint8_t proto, const shared_t *sh, const uint8_t *in, size_t len, uint8_t *out,
                        size_t out_cap, size_t *out_len)
{
    static const uint8_t zero_iv[AES_BLOCK_SIZE] = {0};

    if (proto == 1)
    {
        if (len == 0 || len % AES_BLOCK_SIZE || len > out_cap)
        {
            return false;
        }
        aes256_cbc_decrypt(sh->aes_key, zero_iv, in, out, len);
        *out_len = len;
        return true;
    }
    if (len < 2 * AES_BLOCK_SIZE || len % AES_BLOCK_SIZE || len - AES_BLOCK_SIZE > out_cap)
    {
        return false;
    }
    aes256_cbc_decrypt(sh->aes_key, in, &in[AES_BLOCK_SIZE], out, len - AES_BLOCK_SIZE);
    *out_len = len - AES_BLOCK_SIZE;
    return true;
}

static bool pin_verify(uint8_t proto, const uint8_t key[32], const uint8_t *m1, size_t l1, const uint8_t *m2,
                       size_t l2, const uint8_t *sig, size_t sig_len)
{
    hmac_sha256_ctx_t ctx;
    uint8_t mac[32];
    bool ok;

    hmac_sha256_init(&ctx, key, 32);
    hmac_sha256_update(&ctx, m1, l1);
    if (l2)
    {
        hmac_sha256_update(&ctx, m2, l2);
    }
    hmac_sha256_final(&ctx, mac);

    if (proto == 1)
    {
        ok = sig_len == 16 && crypto_verify16(mac, sig) == 0;
    }
    else
    {
        ok = sig_len == 32 && crypto_verify32(mac, sig) == 0;
    }
    crypto_wipe(mac, sizeof(mac));
    return ok;
}

static bool token_usable(void)
{
    if (pin.token_valid && (HAL_GetTick() - pin.token_tick) > TOKEN_LIFETIME_MS)
    {
        pin.token_valid = false;
    }
    return pin.token_valid;
}

/* verifies pinUvAuthParam over clientDataHash for makeCredential / getAssertion */
static uint8_t verify_token(const slice_t *proto_s, const slice_t *param_s, const uint8_t *msg, size_t msg_len,
                            uint8_t perm, const uint8_t *rp_id_hash)
{
    const uint8_t *param;
    size_t param_len;
    uint64_t proto;

    if (!proto_s->present)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    CHECK(get_uint(proto_s, &proto));
    if (!proto_valid(proto))
    {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    CHECK(get_bytes(param_s, &param, &param_len));

    if (!token_usable() || !pin_verify((uint8_t)proto, pin.token, msg, msg_len, NULL, 0, param, param_len))
    {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!(pin.permissions & perm))
    {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (rp_id_hash)
    {
        if (pin.rp_bound && memcmp(pin.rp_id_hash, rp_id_hash, 32) != 0)
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        if (!pin.rp_bound)
        {
            memcpy(pin.rp_id_hash, rp_id_hash, 32);
            pin.rp_bound = true;
        }
    }
    return CTAP2_OK;
}

/* zero length pinUvAuthParam: platform asks the user to select this authenticator */
static uint8_t zero_length_param(const slice_t *param_s, bool *handled)
{
    const uint8_t *param;
    size_t param_len;

    *handled = false;
    if (!param_s->present)
    {
        return CTAP2_OK;
    }
    CHECK(get_bytes(param_s, &param, &param_len));
    if (param_len != 0)
    {
        return CTAP2_OK;
    }
    *handled = true;
    up_prompt_text("Select this key?", NULL, NULL);
    CHECK(ctap2_wait_up());
    return store_state()->pin_set ? CTAP2_ERR_PIN_INVALID : CTAP2_ERR_PIN_NOT_SET;
}

/* ------------------------------------------------------------------------- */
/* authenticatorGetInfo                                                      */
/* ------------------------------------------------------------------------- */

static uint8_t cmd_get_info(cbor_writer_t *w)
{
    int count = store_rk_count();

    cbor_put_map(w, 14);

    cbor_put_uint(w, 0x01); /* versions */
    cbor_put_array(w, 3);
    cbor_put_text(w, "FIDO_2_0");
    cbor_put_text(w, "FIDO_2_1");
    cbor_put_text(w, "U2F_V2");

    cbor_put_uint(w, 0x02); /* extensions */
    cbor_put_array(w, 2);
    cbor_put_text(w, "credProtect");
    cbor_put_text(w, "hmac-secret");

    cbor_put_uint(w, 0x03);
    cbor_put_bytes(w, aaguid, sizeof(aaguid));

    cbor_put_uint(w, 0x04); /* options, canonical order */
    cbor_put_map(w, 7);
    cbor_put_text(w, "rk");
    cbor_put_bool(w, true);
    cbor_put_text(w, "up");
    cbor_put_bool(w, true);
    cbor_put_text(w, "plat");
    cbor_put_bool(w, false);
    cbor_put_text(w, "credMgmt");
    cbor_put_bool(w, true);
    cbor_put_text(w, "clientPin");
    cbor_put_bool(w, store_state()->pin_set);
    cbor_put_text(w, "pinUvAuthToken");
    cbor_put_bool(w, true);
    cbor_put_text(w, "makeCredUvNotRqd");
    cbor_put_bool(w, true);

    cbor_put_uint(w, 0x05); /* maxMsgSize */
    cbor_put_uint(w, CTAPHID_MAX_MSG);

    cbor_put_uint(w, 0x06); /* pinUvAuthProtocols */
    cbor_put_array(w, 2);
    cbor_put_uint(w, 2);
    cbor_put_uint(w, 1);

    cbor_put_uint(w, 0x07); /* maxCredentialCountInList */
    cbor_put_uint(w, 16);

    cbor_put_uint(w, 0x08); /* maxCredentialIdLength */
    cbor_put_uint(w, CRED_ID_LEN);

    cbor_put_uint(w, 0x09); /* transports */
    cbor_put_array(w, 1);
    cbor_put_text(w, "usb");

    cbor_put_uint(w, 0x0a); /* algorithms */
    cbor_put_array(w, 2);
    cbor_put_map(w, 2);
    cbor_put_text(w, "alg");
    cbor_put_int(w, COSE_ALG_ES256);
    cbor_put_text(w, "type");
    cbor_put_text(w, "public-key");
    cbor_put_map(w, 2);
    cbor_put_text(w, "alg");
    cbor_put_int(w, COSE_ALG_EDDSA);
    cbor_put_text(w, "type");
    cbor_put_text(w, "public-key");

    cbor_put_uint(w, 0x0c); /* forcePINChange */
    cbor_put_bool(w, false);

    cbor_put_uint(w, 0x0d); /* minPINLength */
    cbor_put_uint(w, store_state()->min_pin_len);

    cbor_put_uint(w, 0x0e); /* firmwareVersion */
    cbor_put_uint(w, 1);

    cbor_put_uint(w, 0x14); /* remainingDiscoverableCredentials */
    cbor_put_uint(w, count < STORE_RK_MAX ? STORE_RK_MAX - count : 0);

    return CTAP2_OK;
}

/* ------------------------------------------------------------------------- */
/* authenticatorMakeCredential                                               */
/* ------------------------------------------------------------------------- */

typedef struct
{
    const uint8_t *id;
    size_t id_len;
} rp_t;

static uint8_t rp_cb(const cbor_item_t *k, const cbor_item_t *v, cbor_reader_t *r, void *ctx)
{
    rp_t *rp = ctx;

    if (cbor_text_eq(k, "id") || cbor_text_eq(k, "name") || cbor_text_eq(k, "icon"))
    {
        if (v->type != CBOR_TEXT)
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (cbor_text_eq(k, "id"))
        {
            rp->id = v->ptr;
            rp->id_len = (size_t)v->val;
        }
    }
    return CTAP2_OK;
}

typedef struct
{
    int32_t alg;
    bool found;
} alg_ctx_t;

typedef struct
{
    bool has_alg;
    int64_t alg;
    bool has_type;
    bool public_key;
} alg_param_t;

static uint8_t alg_param_cb(const cbor_item_t *k, const cbor_item_t *v, cbor_reader_t *r, void *ctx)
{
    alg_param_t *p = ctx;

    if (cbor_text_eq(k, "alg"))
    {
        if (!cbor_is_int(v))
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        p->has_alg = true;
        p->alg = cbor_int(v);
    }
    else if (cbor_text_eq(k, "type"))
    {
        if (v->type != CBOR_TEXT)
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        p->has_type = true;
        p->public_key = cbor_text_eq(v, "public-key");
    }
    return CTAP2_OK;
}

static uint8_t alg_cb(const uint8_t *p, size_t len, void *ctx)
{
    alg_ctx_t *a = ctx;
    alg_param_t param = {0};

    CHECK(text_map_foreach(p, len, alg_param_cb, &param));
    if (!param.has_alg || !param.has_type)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!a->found && param.public_key && (param.alg == COSE_ALG_ES256 || param.alg == COSE_ALG_EDDSA))
    {
        a->alg = (int32_t)param.alg;
        a->found = true;
    }
    return CTAP2_OK;
}

typedef struct
{
    const uint8_t *rp_id_hash;
    bool uv;
    bool match;
} exclude_ctx_t;

static uint8_t exclude_cb(const uint8_t *p, size_t len, void *ctx)
{
    exclude_ctx_t *e = ctx;
    descriptor_t d;
    cred_t c;

    CHECK(parse_descriptor(p, len, &d));
    if (!e->match && d.public_key && cred_load(&c, d.id, d.id_len, e->rp_id_hash))
    {
        /* credProtect uvRequired credentials are invisible without UV */
        if ((cred_protect(&c) != 3 || e->uv) && store_cred_live(&c))
        {
            e->match = true;
        }
        cred_wipe(&c);
    }
    return CTAP2_OK;
}

typedef struct
{
    bool hmac_secret;
    uint8_t cred_protect;
} mc_ext_t;

static uint8_t mc_ext_cb(const cbor_item_t *k, const cbor_item_t *v, cbor_reader_t *r, void *ctx)
{
    mc_ext_t *e = ctx;

    if (cbor_text_eq(k, "hmac-secret"))
    {
        if (!cbor_is_bool(v))
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        e->hmac_secret = v->val == CBOR_TRUE;
    }
    else if (cbor_text_eq(k, "credProtect"))
    {
        if (v->type != CBOR_UINT)
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (v->val < 1 || v->val > 3)
        {
            return CTAP1_ERR_INVALID_PARAMETER;
        }
        e->cred_protect = (uint8_t)v->val;
    }
    return CTAP2_OK;
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint8_t cmd_make_credential(const uint8_t *req, size_t len, cbor_writer_t *w)
{
    slice_t p[MAX_PARAMS];
    const uint8_t *cdh;
    size_t cdh_len;
    rp_t rp = {0};
    user_t user;
    alg_ctx_t alg = {0};
    options_t opt;
    mc_ext_t ext = {0};
    uint8_t rp_id_hash[32];
    bool uv = false, rk, handled;
    cred_t c;
    uint8_t cflags, ad_flags, sig[CRED_SIG_MAX];
    size_t n, sig_len;
    cbor_writer_t aw;

    CHECK(parse_params(req, len, p, MAX_PARAMS));
    if (!p[1].present || !p[2].present || !p[3].present || !p[4].present)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    CHECK(get_bytes(&p[1], &cdh, &cdh_len));
    if (cdh_len != 32)
    {
        return CTAP1_ERR_INVALID_LENGTH;
    }
    CHECK(text_map_foreach(p[2].p, p[2].len, rp_cb, &rp));
    if (rp.id == NULL)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    CHECK(parse_user(&p[3], &user));
    CHECK(array_foreach(&p[4], alg_cb, &alg));
    if (p[5].present)
    {
        size_t cnt;
        CHECK(array_count(&p[5], &cnt));
    }
    if (p[6].present)
    {
        CHECK(text_map_foreach(p[6].p, p[6].len, mc_ext_cb, &ext));
    }
    CHECK(parse_options(&p[7], &opt));
    if (p[0x0a].present)
    {
        /* enterprise attestation is not supported */
        return CTAP1_ERR_INVALID_PARAMETER;
    }

    CHECK(zero_length_param(&p[8], &handled));
    if (!alg.found)
    {
        return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }
    if (opt.up == 0)
    {
        return CTAP2_ERR_INVALID_OPTION;
    }
    if (opt.uv == 1 && !p[8].present)
    {
        /* no built-in user verification */
        return CTAP2_ERR_INVALID_OPTION;
    }
    rk = opt.rk == 1;

    sha256(rp.id, rp.id_len, rp_id_hash);

    if (p[8].present)
    {
        CHECK(verify_token(&p[9], &p[8], cdh, cdh_len, PERM_MC, rp_id_hash));
        uv = true;
    }
    else if (store_state()->pin_set && rk)
    {
        return CTAP2_ERR_PUAT_REQUIRED;
    }

    if (p[5].present)
    {
        exclude_ctx_t e = {.rp_id_hash = rp_id_hash, .uv = uv, .match = false};

        CHECK(array_foreach(&p[5], exclude_cb, &e));
        if (e.match)
        {
            up_prompt("Already registered at", rp.id, rp.id_len, user_shown(&user), user_shown_len(&user));
            CHECK(ctap2_wait_up());
            return CTAP2_ERR_CREDENTIAL_EXCLUDED;
        }
    }

    if (rk)
    {
        store_key_t key = store_rk_key(rp_id_hash, user.id, user.id_len);
        if (!store_rk_exists(&key) && store_rk_count() >= STORE_RK_MAX)
        {
            return CTAP2_ERR_KEY_STORE_FULL;
        }
    }

    up_prompt(rk ? "Save passkey for" : "Register at", rp.id, rp.id_len, user_shown(&user), user_shown_len(&user));
    CHECK(ctap2_wait_up());

    cflags = ext.cred_protect;
    if (alg.alg == COSE_ALG_EDDSA)
    {
        cflags |= CRED_FLAG_EDDSA;
    }
    if (rk)
    {
        cflags |= CRED_FLAG_RK;
    }
    if (ext.hmac_secret)
    {
        cflags |= CRED_FLAG_HMAC_SECRET;
    }
    if (!cred_create(&c, rp_id_hash, cflags))
    {
        return CTAP1_ERR_OTHER;
    }

    if (rk)
    {
        memset(&rk_buf, 0, sizeof(rk_buf));
        memcpy(rk_buf.cred_id, c.id, CRED_ID_LEN);
        memcpy(rk_buf.rp_id_hash, rp_id_hash, 32);
        rk_buf.rp_id_len = copy_utf8(rk_buf.rp_id, STORE_RP_ID_MAX, rp.id, rp.id_len);
        memcpy(rk_buf.user_id, user.id, user.id_len);
        rk_buf.user_id_len = (uint8_t)user.id_len;
        rk_buf.user_name_len = copy_utf8(rk_buf.user_name, STORE_USER_STR_MAX, user.name, user.name_len);
        rk_buf.display_name_len =
            copy_utf8(rk_buf.display_name, STORE_USER_STR_MAX, user.display_name, user.display_name_len);
        if (store_rk_put(&rk_buf) < 0)
        {
            cred_wipe(&c);
            return CTAP2_ERR_KEY_STORE_FULL;
        }
    }

    /* authenticator data */
    ad_flags = AD_FLAG_UP | AD_FLAG_AT | (uv ? AD_FLAG_UV : 0);
    if (ext.hmac_secret || ext.cred_protect)
    {
        ad_flags |= AD_FLAG_ED;
    }
    memcpy(auth_data, rp_id_hash, 32);
    auth_data[32] = ad_flags;
    put_be32(&auth_data[33], store_counter_next());
    memcpy(&auth_data[37], aaguid, 16);
    auth_data[53] = 0;
    auth_data[54] = CRED_ID_LEN;
    memcpy(&auth_data[55], c.id, CRED_ID_LEN);
    n = 55 + CRED_ID_LEN;

    cbor_writer_init(&aw, &auth_data[n], AUTH_DATA_MAX - n);
    cred_put_cose_key(&aw, &c);
    if (ad_flags & AD_FLAG_ED)
    {
        cbor_put_map(&aw, (ext.cred_protect ? 1 : 0) + (ext.hmac_secret ? 1 : 0));
        if (ext.cred_protect)
        {
            cbor_put_text(&aw, "credProtect");
            cbor_put_uint(&aw, ext.cred_protect);
        }
        if (ext.hmac_secret)
        {
            cbor_put_text(&aw, "hmac-secret");
            cbor_put_bool(&aw, true);
        }
    }
    if (aw.err)
    {
        cred_wipe(&c);
        return CTAP1_ERR_OTHER;
    }
    n += aw.len;

    /* packed self attestation */
    memcpy(&auth_data[n], cdh, 32);
    sig_len = cred_sign(&c, auth_data, n + 32, sig);
    cred_wipe(&c);
    if (sig_len == 0)
    {
        return CTAP1_ERR_OTHER;
    }

    cbor_put_map(w, 3);
    cbor_put_uint(w, 1);
    cbor_put_text(w, "packed");
    cbor_put_uint(w, 2);
    cbor_put_bytes(w, auth_data, n);
    cbor_put_uint(w, 3);
    cbor_put_map(w, 2);
    cbor_put_text(w, "alg");
    cbor_put_int(w, alg.alg);
    cbor_put_text(w, "sig");
    cbor_put_bytes(w, sig, sig_len);
    return CTAP2_OK;
}

/* ------------------------------------------------------------------------- */
/* authenticatorGetAssertion / authenticatorGetNextAssertion                 */
/* ------------------------------------------------------------------------- */

typedef struct
{
    const uint8_t *rp_id_hash;
    bool uv;
    bool found;
    uint8_t id[CRED_ID_LEN];
} allow_ctx_t;

static uint8_t allow_cb(const uint8_t *p, size_t len, void *ctx)
{
    allow_ctx_t *a = ctx;
    descriptor_t d;
    cred_t c;

    CHECK(parse_descriptor(p, len, &d));
    if (!a->found && d.public_key && cred_load(&c, d.id, d.id_len, a->rp_id_hash))
    {
        if ((cred_protect(&c) != 3 || a->uv) && store_cred_live(&c))
        {
            memcpy(a->id, c.id, CRED_ID_LEN);
            a->found = true;
        }
        cred_wipe(&c);
    }
    return CTAP2_OK;
}

static bool collect_rk_cb(const store_key_t *key, const store_rk_t *rk, void *ctx)
{
    uint8_t level;

    if (memcmp(rk->rp_id_hash, ga.rp_id_hash, 32) != 0 || ga.count >= STORE_RK_MAX)
    {
        return true;
    }
    /* credProtect 2 and 3 are not discoverable without user verification */
    level = rk->cred_id[1] & CRED_FLAG_PROTECT_MASK;
    if (level >= 2 && !ga.uv)
    {
        return true;
    }

    /* insertion sort, most recent first */
    uint8_t i = ga.count++;
    while (i > 0 && ga.created[i - 1] < rk->created)
    {
        ga.keys[i] = ga.keys[i - 1];
        ga.created[i] = ga.created[i - 1];
        i--;
    }
    ga.keys[i] = *key;
    ga.created[i] = rk->created;
    return true;
}

static uint8_t ga_ext_cb(const cbor_item_t *k, const cbor_item_t *v, cbor_reader_t *r, void *ctx)
{
    slice_t *hmac = ctx;

    if (cbor_text_eq(k, "hmac-secret"))
    {
        if (v->type != CBOR_MAP)
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        if (!cbor_skip_rest(r, v))
        {
            return CTAP2_ERR_INVALID_CBOR;
        }
        hmac->p = v->start;
        hmac->len = (size_t)(r->p - v->start);
        hmac->present = true;
    }
    return CTAP2_OK;
}

static uint8_t parse_hmac_secret(const slice_t *s)
{
    slice_t hp[5];
    const uint8_t *salt_enc, *salt_auth;
    size_t salt_enc_len, salt_auth_len, plain_len;
    uint64_t proto = 1;

    CHECK(parse_params(s->p, s->len, hp, 5));
    if (!hp[1].present || !hp[2].present || !hp[3].present)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (hp[4].present)
    {
        CHECK(get_uint(&hp[4], &proto));
        if (!proto_valid(proto))
        {
            return CTAP1_ERR_INVALID_PARAMETER;
        }
    }
    CHECK(get_bytes(&hp[2], &salt_enc, &salt_enc_len));
    CHECK(get_bytes(&hp[3], &salt_auth, &salt_auth_len));
    CHECK(pin_decapsulate((uint8_t)proto, &hp[1], &ga.hmac_shared));

    if (!pin_verify((uint8_t)proto, ga.hmac_shared.hmac_key, salt_enc, salt_enc_len, NULL, 0, salt_auth,
                    salt_auth_len))
    {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!pin_decrypt((uint8_t)proto, &ga.hmac_shared, salt_enc, salt_enc_len, ga.salt, sizeof(ga.salt),
                     &plain_len) ||
        (plain_len != 32 && plain_len != 64))
    {
        return CTAP1_ERR_INVALID_LENGTH;
    }
    ga.salt_len = (uint8_t)plain_len;
    ga.hmac_proto = (uint8_t)proto;
    ga.hmac = true;
    return CTAP2_OK;
}

static uint8_t build_assertion(cbor_writer_t *w, bool first)
{
    store_rk_t *rk = NULL;
    store_key_t key;
    cred_t c;
    uint8_t ad_flags, sig[CRED_SIG_MAX];
    uint8_t hmac_out[AES_BLOCK_SIZE + 64];
    size_t hmac_out_len = 0, n, sig_len;
    bool use_hmac;

    if (ga.from_rk)
    {
        if (store_rk_get(&ga.keys[ga.idx], &rk_buf) < 0)
        {
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        rk = &rk_buf;
        memcpy(ga.cred_id, rk->cred_id, CRED_ID_LEN);
    }
    else if (ga.cred_id[1] & CRED_FLAG_RK)
    {
        /* allowList entry of a discoverable credential - return the user handle; without its
           record it was deleted or replaced and must not sign */
        if (!store_rk_find_cred(ga.cred_id, CRED_ID_LEN, &key, &rk_buf))
        {
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        rk = &rk_buf;
    }

    if (!cred_load(&c, ga.cred_id, CRED_ID_LEN, ga.rp_id_hash))
    {
        return CTAP2_ERR_NO_CREDENTIALS;
    }

    use_hmac = ga.hmac && (c.flags & CRED_FLAG_HMAC_SECRET);
    if (use_hmac)
    {
        uint8_t cred_random[32], out[64];

        cred_hmac_secret_key(&c, ga.uv, cred_random);
        hmac_sha256(cred_random, 32, ga.salt, 32, out);
        if (ga.salt_len == 64)
        {
            hmac_sha256(cred_random, 32, &ga.salt[32], 32, &out[32]);
        }
        hmac_out_len = pin_encrypt(ga.hmac_proto, &ga.hmac_shared, out, ga.salt_len, hmac_out);
        crypto_wipe(cred_random, sizeof(cred_random));
        crypto_wipe(out, sizeof(out));
    }

    ad_flags = (ga.up ? AD_FLAG_UP : 0) | (ga.uv ? AD_FLAG_UV : 0) | (use_hmac ? AD_FLAG_ED : 0);
    memcpy(auth_data, ga.rp_id_hash, 32);
    auth_data[32] = ad_flags;
    put_be32(&auth_data[33], store_counter_next());
    n = 37;
    if (use_hmac)
    {
        cbor_writer_t aw;

        cbor_writer_init(&aw, &auth_data[n], AUTH_DATA_MAX - n);
        cbor_put_map(&aw, 1);
        cbor_put_text(&aw, "hmac-secret");
        cbor_put_bytes(&aw, hmac_out, hmac_out_len);
        n += aw.len;
    }
    memcpy(&auth_data[n], ga.cdh, 32);
    sig_len = cred_sign(&c, auth_data, n + 32, sig);
    cred_wipe(&c);
    if (sig_len == 0)
    {
        return CTAP1_ERR_OTHER;
    }

    cbor_put_map(w, 3 + (rk ? 1 : 0) + ((first && ga.count > 1) ? 1 : 0) + (ga.selected ? 1 : 0));
    cbor_put_uint(w, 1);
    cbor_put_map(w, 2);
    cbor_put_text(w, "id");
    cbor_put_bytes(w, ga.cred_id, CRED_ID_LEN);
    cbor_put_text(w, "type");
    cbor_put_text(w, "public-key");
    cbor_put_uint(w, 2);
    cbor_put_bytes(w, auth_data, n);
    cbor_put_uint(w, 3);
    cbor_put_bytes(w, sig, sig_len);
    if (rk)
    {
        /* user identifiable information only after user verification */
        bool name = ga.uv && rk->user_name_len;
        bool display = ga.uv && rk->display_name_len;

        cbor_put_uint(w, 4);
        cbor_put_map(w, 1 + (name ? 1 : 0) + (display ? 1 : 0));
        cbor_put_text(w, "id");
        cbor_put_bytes(w, rk->user_id, rk->user_id_len);
        if (name)
        {
            cbor_put_text(w, "name");
            cbor_put_textn(w, rk->user_name, rk->user_name_len);
        }
        if (display)
        {
            cbor_put_text(w, "displayName");
            cbor_put_textn(w, rk->display_name, rk->display_name_len);
        }
    }
    if (first && ga.count > 1)
    {
        cbor_put_uint(w, 5);
        cbor_put_uint(w, ga.count);
    }
    if (ga.selected)
    {
        cbor_put_uint(w, 6); /* userSelected */
        cbor_put_bool(w, true);
    }
    return CTAP2_OK;
}

static void ga_prompt_rk(const char *action, const store_rk_t *rk)
{
    bool name = rk->user_name_len != 0;

    up_prompt(action, ga.rp_id, ga.rp_id_len, name ? rk->user_name : rk->display_name,
              name ? rk->user_name_len : rk->display_name_len);
}

/* what a getAssertion touch confirms: the account when it's stored */
static void ga_prompt(void)
{
    store_key_t key;

    /* a discoverable credential has a name, one from the allow list only if stored */
    if ((ga.from_rk && store_rk_get(&ga.keys[0], &rk_buf) == 0) ||
        (!ga.from_rk && (ga.cred_id[1] & CRED_FLAG_RK) && store_rk_find_cred(ga.cred_id, CRED_ID_LEN, &key, &rk_buf)))
    {
        ga_prompt_rk("Sign in to", &rk_buf);
        return;
    }
    up_prompt("Sign in to", ga.rp_id, ga.rp_id_len, NULL, 0);
}

/* account i of the list, "Sign in to  2/3", or the cancel entry after the last one */
static void ga_show(uint8_t i)
{
    char action[DISPLAY_COLS + 1] = "Sign in to";
    size_t n = DISPLAY_COLS;

    if (i == ga.count)
    {
        up_hint("OK: cancel  Next: back");
        up_prompt_text("Cancel sign-in?", NULL, NULL);
        return;
    }
    memset(&action[10], ' ', DISPLAY_COLS - 10);
    action[n] = '\0';
    action[--n] = (char)('0' + ga.count % 10);
    if (ga.count >= 10)
    {
        action[--n] = (char)('0' + ga.count / 10);
    }
    action[--n] = '/';
    action[--n] = (char)('0' + (i + 1) % 10);
    if (i + 1 >= 10)
    {
        action[--n] = (char)('0' + (i + 1) / 10);
    }
    up_hint("OK: select  Next: other");
    if (store_rk_get(&ga.keys[i], &rk_buf) == 0)
    {
        ga_prompt_rk(action, &rk_buf);
    }
    else
    {
        up_prompt(action, ga.rp_id, ga.rp_id_len, NULL, 0);
    }
}

static uint8_t cmd_get_assertion(const uint8_t *req, size_t len, cbor_writer_t *w)
{
    slice_t p[MAX_PARAMS];
    slice_t hmac = {0};
    const uint8_t *rp_id, *cdh;
    size_t rp_id_len, cdh_len, allow_count = 0;
    options_t opt;
    bool handled;

    memset(&ga, 0, sizeof(ga));

    CHECK(parse_params(req, len, p, MAX_PARAMS));
    if (!p[1].present || !p[2].present)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    CHECK(get_text(&p[1], &rp_id, &rp_id_len));
    CHECK(get_bytes(&p[2], &cdh, &cdh_len));
    if (cdh_len != 32)
    {
        return CTAP1_ERR_INVALID_LENGTH;
    }
    if (p[3].present)
    {
        CHECK(array_count(&p[3], &allow_count));
    }
    if (p[4].present)
    {
        CHECK(text_map_foreach(p[4].p, p[4].len, ga_ext_cb, &hmac));
    }
    CHECK(parse_options(&p[5], &opt));

    CHECK(zero_length_param(&p[6], &handled));
    if (opt.rk != -1)
    {
        return CTAP2_ERR_UNSUPPORTED_OPTION;
    }
    if (opt.uv == 1 && !p[6].present)
    {
        return CTAP2_ERR_INVALID_OPTION;
    }

    sha256(rp_id, rp_id_len, ga.rp_id_hash);
    ga.rp_id = rp_id;
    ga.rp_id_len = rp_id_len;
    memcpy(ga.cdh, cdh, 32);
    ga.up = opt.up != 0;

    if (p[6].present)
    {
        CHECK(verify_token(&p[7], &p[6], cdh, cdh_len, PERM_GA, ga.rp_id_hash));
        ga.uv = true;
    }

    if (allow_count)
    {
        allow_ctx_t a = {.rp_id_hash = ga.rp_id_hash, .uv = ga.uv, .found = false};

        CHECK(array_foreach(&p[3], allow_cb, &a));
        if (a.found)
        {
            memcpy(ga.cred_id, a.id, CRED_ID_LEN);
            ga.count = 1;
        }
    }
    else
    {
        ga.from_rk = true;
        store_rk_foreach(collect_rk_cb, NULL);
    }
    if (ga.count == 0)
    {
        return CTAP2_ERR_NO_CREDENTIALS;
    }

    if (hmac.present)
    {
        CHECK(parse_hmac_secret(&hmac));
    }

    if (ga.up && ga.count > 1)
    {
        /* several discoverable credentials: the user picks one on the display, only it is returned */
        uint8_t i;

        CHECK(wait_choice(ga.count, ga_show, &i));
        ga.keys[0] = ga.keys[i];
        ga.count = 1;
        ga.selected = true;
    }
    else if (ga.up)
    {
        ga_prompt();
        CHECK(ctap2_wait_up());
    }

    CHECK(build_assertion(w, true));
    ga.idx = 1;
    ga.tick = HAL_GetTick();
    ga.valid = ga.count > 1;
    return CTAP2_OK;
}

static uint8_t cmd_get_next_assertion(cbor_writer_t *w)
{
    if (!ga.valid || ga.idx >= ga.count || (HAL_GetTick() - ga.tick) > NEXT_ASSERTION_MS)
    {
        ga.valid = false;
        return CTAP2_ERR_NOT_ALLOWED;
    }
    CHECK(build_assertion(w, false));
    ga.idx++;
    ga.tick = HAL_GetTick();
    return CTAP2_OK;
}

/* ------------------------------------------------------------------------- */
/* authenticatorClientPIN                                                    */
/* ------------------------------------------------------------------------- */

static uint8_t pin_set_new(uint8_t proto, const shared_t *sh, const uint8_t *enc, size_t enc_len)
{
    uint8_t plain[64];
    size_t plain_len, pin_len, cps = 0;
    store_state_t *st = store_state();
    uint8_t hash[32];

    if (!pin_decrypt(proto, sh, enc, enc_len, plain, sizeof(plain), &plain_len) || plain_len != 64)
    {
        crypto_wipe(plain, sizeof(plain));
        return CTAP2_ERR_PIN_POLICY_VIOLATION;
    }
    for (pin_len = 0; pin_len < plain_len && plain[pin_len]; pin_len++)
    {
        /* count UTF-8 code points */
        if ((plain[pin_len] & 0xc0) != 0x80)
        {
            cps++;
        }
    }
    if (cps < st->min_pin_len || pin_len > 63)
    {
        crypto_wipe(plain, sizeof(plain));
        return CTAP2_ERR_PIN_POLICY_VIOLATION;
    }

    sha256(plain, pin_len, hash);
    crypto_wipe(plain, sizeof(plain));
    memcpy(st->pin_hash, hash, sizeof(st->pin_hash));
    crypto_wipe(hash, sizeof(hash));
    st->pin_set = 1;
    if (store_save_state() < 0 || store_set_pin_retries(STORE_PIN_RETRIES) < 0)
    {
        return CTAP1_ERR_OTHER;
    }
    pin_new_token();
    return CTAP2_OK;
}

/* decrypts pinHashEnc and compares with the stored PIN hash, handles retry counters */
static uint8_t pin_check_hash(uint8_t proto, const shared_t *sh, const uint8_t *enc, size_t enc_len)
{
    store_state_t *st = store_state();
    uint8_t plain[16];
    size_t plain_len;
    bool ok;

    if (store_pin_retries() == 0)
    {
        return CTAP2_ERR_PIN_BLOCKED;
    }
    if (pin.consecutive_fails >= PIN_MAX_CONSECUTIVE)
    {
        return CTAP2_ERR_PIN_AUTH_BLOCKED;
    }

    /* decrement first, a power loss must not give a free attempt */
    if (store_set_pin_retries((uint8_t)(store_pin_retries() - 1U)) < 0)
    {
        return CTAP1_ERR_OTHER;
    }

    ok = pin_decrypt(proto, sh, enc, enc_len, plain, sizeof(plain), &plain_len) && plain_len == 16 && crypto_verify16(plain, st->pin_hash) == 0;
    crypto_wipe(plain, sizeof(plain));

    if (!ok)
    {
        pin_new_key_agreement();
        pin.consecutive_fails++;
        if (store_pin_retries() == 0)
        {
            return CTAP2_ERR_PIN_BLOCKED;
        }
        if (pin.consecutive_fails >= PIN_MAX_CONSECUTIVE)
        {
            return CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
        return CTAP2_ERR_PIN_INVALID;
    }

    pin.consecutive_fails = 0;
    if (store_set_pin_retries(STORE_PIN_RETRIES) < 0)
    {
        return CTAP1_ERR_OTHER;
    }
    return CTAP2_OK;
}

static uint8_t cmd_client_pin(const uint8_t *req, size_t len, cbor_writer_t *w)
{
    slice_t p[MAX_PARAMS];
    uint64_t proto = 0, sub;
    store_state_t *st = store_state();
    const uint8_t *param, *new_enc, *hash_enc;
    size_t param_len, new_enc_len, hash_enc_len;
    shared_t sh;
    uint8_t enc[32 + AES_BLOCK_SIZE];
    size_t enc_len;

    CHECK(parse_params(req, len, p, MAX_PARAMS));
    if (!p[2].present)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    CHECK(get_uint(&p[2], &sub));
    if (p[1].present)
    {
        CHECK(get_uint(&p[1], &proto));
    }

    if (sub == 0x01)
    {
        /* getPINRetries */
        cbor_put_map(w, 2);
        cbor_put_uint(w, 3);
        cbor_put_uint(w, store_pin_retries());
        cbor_put_uint(w, 4); /* powerCycleState */
        cbor_put_bool(w, pin.consecutive_fails >= PIN_MAX_CONSECUTIVE);
        return CTAP2_OK;
    }

    if (sub < 0x02 || sub > 0x09)
    {
        return CTAP2_ERR_INVALID_SUBCOMMAND;
    }
    if (sub == 0x06 || sub == 0x07 || sub == 0x08)
    {
        /* no built-in UV, no getPinUvAuthTokenUsingUvWithPermissions/getUVRetries */
        return CTAP2_ERR_INVALID_SUBCOMMAND;
    }
    if (!p[1].present)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!proto_valid(proto))
    {
        return CTAP1_ERR_INVALID_PARAMETER;
    }

    if (sub == 0x02)
    {
        /* getKeyAgreement */
        if (!pin.ka_valid)
        {
            pin_new_key_agreement();
        }
        if (!pin.ka_valid)
        {
            return CTAP1_ERR_OTHER;
        }
        cbor_put_map(w, 1);
        cbor_put_uint(w, 1);
        cbor_put_map(w, 5);
        cbor_put_int(w, 1);
        cbor_put_int(w, 2);
        cbor_put_int(w, 3);
        cbor_put_int(w, COSE_ALG_ECDH);
        cbor_put_int(w, -1);
        cbor_put_int(w, 1);
        cbor_put_int(w, -2);
        cbor_put_bytes(w, pin.ka_pub, 32);
        cbor_put_int(w, -3);
        cbor_put_bytes(w, &pin.ka_pub[32], 32);
        return CTAP2_OK;
    }

    if (!p[3].present)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    if (sub == 0x03)
    {
        /* setPIN */
        if (!p[4].present || !p[5].present)
        {
            return CTAP2_ERR_MISSING_PARAMETER;
        }
        if (st->pin_set)
        {
            return CTAP2_ERR_NOT_ALLOWED;
        }
        CHECK(get_bytes(&p[4], &param, &param_len));
        CHECK(get_bytes(&p[5], &new_enc, &new_enc_len));
        CHECK(pin_decapsulate((uint8_t)proto, &p[3], &sh));
        if (!pin_verify((uint8_t)proto, sh.hmac_key, new_enc, new_enc_len, NULL, 0, param, param_len))
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        return pin_set_new((uint8_t)proto, &sh, new_enc, new_enc_len);
    }

    if (sub == 0x04)
    {
        /* changePIN */
        if (!p[4].present || !p[5].present || !p[6].present)
        {
            return CTAP2_ERR_MISSING_PARAMETER;
        }
        if (!st->pin_set)
        {
            return CTAP2_ERR_PIN_NOT_SET;
        }
        if (store_pin_retries() == 0)
        {
            return CTAP2_ERR_PIN_BLOCKED;
        }
        CHECK(get_bytes(&p[4], &param, &param_len));
        CHECK(get_bytes(&p[5], &new_enc, &new_enc_len));
        CHECK(get_bytes(&p[6], &hash_enc, &hash_enc_len));
        CHECK(pin_decapsulate((uint8_t)proto, &p[3], &sh));
        if (!pin_verify((uint8_t)proto, sh.hmac_key, new_enc, new_enc_len, hash_enc, hash_enc_len, param,
                        param_len))
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        CHECK(pin_check_hash((uint8_t)proto, &sh, hash_enc, hash_enc_len));
        return pin_set_new((uint8_t)proto, &sh, new_enc, new_enc_len);
    }

    /* getPinToken (0x05), getPinUvAuthTokenUsingPinWithPermissions (0x09) */
    if (!p[6].present)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    uint64_t perms = PERM_MC | PERM_GA;
    const uint8_t *rp_id = NULL;
    size_t rp_id_len = 0;

    if (sub == 0x05)
    {
        if (p[9].present || p[0x0a].present)
        {
            return CTAP1_ERR_INVALID_PARAMETER;
        }
    }
    else
    {
        if (!p[9].present)
        {
            return CTAP2_ERR_MISSING_PARAMETER;
        }
        CHECK(get_uint(&p[9], &perms));
        if (perms == 0)
        {
            return CTAP1_ERR_INVALID_PARAMETER;
        }
        if (perms & (PERM_BE | PERM_LBW | PERM_ACFG | ~0x3fULL))
        {
            return CTAP2_ERR_UNAUTHORIZED_PERMISSION;
        }
        if (p[0x0a].present)
        {
            CHECK(get_text(&p[0x0a], &rp_id, &rp_id_len));
        }
        else if (perms & (PERM_MC | PERM_GA))
        {
            return CTAP2_ERR_MISSING_PARAMETER;
        }
    }
    if (!st->pin_set)
    {
        return CTAP2_ERR_PIN_NOT_SET;
    }

    CHECK(get_bytes(&p[6], &hash_enc, &hash_enc_len));
    CHECK(pin_decapsulate((uint8_t)proto, &p[3], &sh));
    CHECK(pin_check_hash((uint8_t)proto, &sh, hash_enc, hash_enc_len));

    pin_new_token();
    pin.token_valid = true;
    pin.token_tick = HAL_GetTick();
    pin.permissions = (uint8_t)perms;
    if (rp_id)
    {
        sha256(rp_id, rp_id_len, pin.rp_id_hash);
        pin.rp_bound = true;
    }

    enc_len = pin_encrypt((uint8_t)proto, &sh, pin.token, sizeof(pin.token), enc);
    crypto_wipe(&sh, sizeof(sh));
    cbor_put_map(w, 1);
    cbor_put_uint(w, 2);
    cbor_put_bytes(w, enc, enc_len);
    return CTAP2_OK;
}

/* ------------------------------------------------------------------------- */
/* authenticatorReset / authenticatorSelection                               */
/* ------------------------------------------------------------------------- */

static uint8_t cmd_reset(void)
{
    if (HAL_GetTick() > RESET_WINDOW_MS)
    {
        return CTAP2_ERR_NOT_ALLOWED;
    }
    up_prompt_text("Reset this key?", "Deletes all credentials", "and the PIN");
    CHECK(ctap2_wait_up());
    if (store_reset() < 0)
    {
        return CTAP1_ERR_OTHER;
    }
    u2f_reset();
    pin.ka_valid = false;
    pin.consecutive_fails = 0;
    pin_new_token();
    return CTAP2_OK;
}

/* ------------------------------------------------------------------------- */
/* authenticatorCredentialManagement                                         */
/* ------------------------------------------------------------------------- */

static bool collect_rp_cb(const store_key_t *key, const store_rk_t *rk, void *ctx)
{
    for (uint8_t i = 0; i < cm.rp_count; i++)
    {
        if (memcmp(cm.rp_hash[i], rk->rp_id_hash, 32) == 0)
        {
            return true;
        }
    }
    if (cm.rp_count < STORE_RK_MAX)
    {
        memcpy(cm.rp_hash[cm.rp_count], rk->rp_id_hash, 32);
        cm.rp_key[cm.rp_count] = *key;
        cm.rp_count++;
    }
    return true;
}

static bool collect_cred_cb(const store_key_t *key, const store_rk_t *rk, void *ctx)
{
    const uint8_t *rp_id_hash = ctx;

    if (memcmp(rk->rp_id_hash, rp_id_hash, 32) == 0 && cm.cred_count < STORE_RK_MAX)
    {
        cm.cred_key[cm.cred_count++] = *key;
    }
    return true;
}

static uint8_t put_rp(cbor_writer_t *w, bool first)
{
    if (store_rk_get(&cm.rp_key[cm.rp_idx], &rk_buf) < 0)
    {
        return CTAP2_ERR_NO_CREDENTIALS;
    }
    cbor_put_map(w, first ? 3 : 2);
    cbor_put_uint(w, 3);
    cbor_put_map(w, 1);
    cbor_put_text(w, "id");
    cbor_put_textn(w, rk_buf.rp_id, rk_buf.rp_id_len);
    cbor_put_uint(w, 4);
    cbor_put_bytes(w, rk_buf.rp_id_hash, 32);
    if (first)
    {
        cbor_put_uint(w, 5);
        cbor_put_uint(w, cm.rp_count);
    }
    cm.rp_idx++;
    return CTAP2_OK;
}

static uint8_t put_cred(cbor_writer_t *w, bool first)
{
    cred_t c;
    uint8_t level;

    if (store_rk_get(&cm.cred_key[cm.cred_idx], &rk_buf) < 0 ||
        !cred_load(&c, rk_buf.cred_id, CRED_ID_LEN, rk_buf.rp_id_hash))
    {
        return CTAP2_ERR_NO_CREDENTIALS;
    }
    level = cred_protect(&c);

    cbor_put_map(w, 3 + (first ? 1 : 0) + (level ? 1 : 0));
    cbor_put_uint(w, 6);
    cbor_put_map(w, 1 + (rk_buf.user_name_len ? 1 : 0) + (rk_buf.display_name_len ? 1 : 0));
    cbor_put_text(w, "id");
    cbor_put_bytes(w, rk_buf.user_id, rk_buf.user_id_len);
    if (rk_buf.user_name_len)
    {
        cbor_put_text(w, "name");
        cbor_put_textn(w, rk_buf.user_name, rk_buf.user_name_len);
    }
    if (rk_buf.display_name_len)
    {
        cbor_put_text(w, "displayName");
        cbor_put_textn(w, rk_buf.display_name, rk_buf.display_name_len);
    }
    cbor_put_uint(w, 7);
    cbor_put_map(w, 2);
    cbor_put_text(w, "id");
    cbor_put_bytes(w, rk_buf.cred_id, CRED_ID_LEN);
    cbor_put_text(w, "type");
    cbor_put_text(w, "public-key");
    cbor_put_uint(w, 8);
    cred_put_cose_key(w, &c);
    cred_wipe(&c);
    if (first)
    {
        cbor_put_uint(w, 9);
        cbor_put_uint(w, cm.cred_count);
    }
    if (level)
    {
        cbor_put_uint(w, 0x0a);
        cbor_put_uint(w, level);
    }
    cm.cred_idx++;
    return CTAP2_OK;
}

static uint8_t cmd_cred_mgmt(const uint8_t *req, size_t len, cbor_writer_t *w)
{
    slice_t p[MAX_PARAMS];
    slice_t sp[MAX_PARAMS];
    uint64_t sub;
    uint8_t sub_byte;
    int count;
    descriptor_t d;
    store_key_t key;

    CHECK(parse_params(req, len, p, MAX_PARAMS));
    if (!p[1].present)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    CHECK(get_uint(&p[1], &sub));
    if (p[2].present)
    {
        CHECK(parse_params(p[2].p, p[2].len, sp, MAX_PARAMS));
    }
    else
    {
        memset(sp, 0, sizeof(sp));
    }

    if (sub == 0x03)
    {
        /* enumerateRPsGetNextRP */
        if (!cm.rp_valid || cm.rp_idx >= cm.rp_count)
        {
            return CTAP2_ERR_NOT_ALLOWED;
        }
        return put_rp(w, false);
    }
    if (sub == 0x05)
    {
        /* enumerateCredentialsGetNextCredential */
        if (!cm.cred_valid || cm.cred_idx >= cm.cred_count)
        {
            return CTAP2_ERR_NOT_ALLOWED;
        }
        return put_cred(w, false);
    }
    if (sub < 0x01 || sub > 0x07)
    {
        return CTAP2_ERR_INVALID_SUBCOMMAND;
    }

    /* all other subcommands need pinUvAuthParam = authenticate(token, subCommand | subCommandParams) */
    if (!p[4].present)
    {
        return CTAP2_ERR_PUAT_REQUIRED;
    }
    sub_byte = (uint8_t)sub;
    {
        const uint8_t *param;
        size_t param_len;
        uint64_t proto;

        if (!p[3].present)
        {
            return CTAP2_ERR_MISSING_PARAMETER;
        }
        CHECK(get_uint(&p[3], &proto));
        if (!proto_valid(proto))
        {
            return CTAP1_ERR_INVALID_PARAMETER;
        }
        CHECK(get_bytes(&p[4], &param, &param_len));
        if (!token_usable() ||
            !pin_verify((uint8_t)proto, pin.token, &sub_byte, 1, p[2].p, p[2].present ? p[2].len : 0, param,
                        param_len) ||
            !(pin.permissions & PERM_CM))
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
    }

    switch (sub)
    {
    case 0x01: /* getCredsMetadata */
        if (pin.rp_bound)
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        count = store_rk_count();
        cbor_put_map(w, 2);
        cbor_put_uint(w, 1);
        cbor_put_uint(w, count);
        cbor_put_uint(w, 2);
        cbor_put_uint(w, count < STORE_RK_MAX ? STORE_RK_MAX - count : 0);
        return CTAP2_OK;

    case 0x02: /* enumerateRPsBegin */
        if (pin.rp_bound)
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        cm.rp_count = 0;
        cm.rp_idx = 0;
        store_rk_foreach(collect_rp_cb, NULL);
        if (cm.rp_count == 0)
        {
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        cm.rp_valid = true;
        return put_rp(w, true);

    case 0x04: /* enumerateCredentialsBegin */
    {
        const uint8_t *hash;
        size_t hash_len;

        if (!sp[1].present)
        {
            return CTAP2_ERR_MISSING_PARAMETER;
        }
        CHECK(get_bytes(&sp[1], &hash, &hash_len));
        if (hash_len != 32)
        {
            return CTAP1_ERR_INVALID_PARAMETER;
        }
        if (pin.rp_bound && memcmp(pin.rp_id_hash, hash, 32) != 0)
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        cm.cred_count = 0;
        cm.cred_idx = 0;
        store_rk_foreach(collect_cred_cb, (void *)hash);
        if (cm.cred_count == 0)
        {
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        cm.cred_valid = true;
        return put_cred(w, true);
    }

    case 0x06: /* deleteCredential */
        if (!sp[2].present)
        {
            return CTAP2_ERR_MISSING_PARAMETER;
        }
        CHECK(parse_descriptor(sp[2].p, sp[2].len, &d));
        if (!store_rk_find_cred(d.id, d.id_len, &key, &rk_buf))
        {
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        if (pin.rp_bound && memcmp(pin.rp_id_hash, rk_buf.rp_id_hash, 32) != 0)
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        return store_rk_delete(&key) < 0 ? CTAP1_ERR_OTHER : CTAP2_OK;

    case 0x07: /* updateUserInformation */
    {
        user_t user;

        if (!sp[2].present || !sp[3].present)
        {
            return CTAP2_ERR_MISSING_PARAMETER;
        }
        CHECK(parse_descriptor(sp[2].p, sp[2].len, &d));
        CHECK(parse_user(&sp[3], &user));
        if (!store_rk_find_cred(d.id, d.id_len, &key, &rk_buf))
        {
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        if (pin.rp_bound && memcmp(pin.rp_id_hash, rk_buf.rp_id_hash, 32) != 0)
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        if (user.id_len != rk_buf.user_id_len || memcmp(user.id, rk_buf.user_id, user.id_len) != 0)
        {
            return CTAP1_ERR_INVALID_PARAMETER;
        }
        rk_buf.user_name_len = copy_utf8(rk_buf.user_name, STORE_USER_STR_MAX, user.name, user.name_len);
        rk_buf.display_name_len =
            copy_utf8(rk_buf.display_name, STORE_USER_STR_MAX, user.display_name, user.display_name_len);
        return store_rk_put(&rk_buf) < 0 ? CTAP1_ERR_OTHER : CTAP2_OK;
    }

    default:
        return CTAP2_ERR_INVALID_SUBCOMMAND;
    }
}

/* ------------------------------------------------------------------------- */

void ctap2_init(void)
{
    memset(&pin, 0, sizeof(pin));
    pin_new_token();
}

size_t ctap2_process(const uint8_t *req, size_t len, uint8_t *resp, size_t cap)
{
    cbor_writer_t w;
    uint8_t cmd = req[0];
    uint8_t status;

    cbor_writer_init(&w, &resp[1], cap - 1);
    req++;
    len--;

    if (cmd != CMD_GET_NEXT_ASSERTION)
    {
        ga.valid = false;
    }
    if (cmd != CMD_CRED_MGMT)
    {
        cm.rp_valid = false;
        cm.cred_valid = false;
    }

    switch (cmd)
    {
    case CMD_MAKE_CREDENTIAL:
        status = cmd_make_credential(req, len, &w);
        break;
    case CMD_GET_ASSERTION:
        status = cmd_get_assertion(req, len, &w);
        break;
    case CMD_GET_NEXT_ASSERTION:
        status = cmd_get_next_assertion(&w);
        break;
    case CMD_GET_INFO:
        status = cmd_get_info(&w);
        break;
    case CMD_CLIENT_PIN:
        status = cmd_client_pin(req, len, &w);
        break;
    case CMD_RESET:
        status = cmd_reset();
        break;
    case CMD_CRED_MGMT:
        status = cmd_cred_mgmt(req, len, &w);
        break;
    case CMD_SELECTION:
        up_prompt_text("Select this key?", NULL, NULL);
        status = ctap2_wait_up();
        break;
    default:
        status = CTAP1_ERR_INVALID_COMMAND;
        break;
    }

    if (status == CTAP2_OK && w.err)
    {
        status = CTAP1_ERR_OTHER;
    }
    resp[0] = status;
    return status == CTAP2_OK ? 1 + w.len : 1;
}
