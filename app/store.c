#include <string.h>

#include "monocypher.h"

#include "kv.h"
#include "nv.h"
#include "rng.h"
#include "sha256.h"

#include "store.h"

#define STATE_MAGIC 0x46494432U /* "FID2" */

/* kv key of the state; credential keys are HMAC outputs, a clash is out of reach */
static const uint8_t state_key[KV_KEY_SIZE] = {'s', 't', 'a', 't', 'e', 0, 0, 0};

_Static_assert(sizeof(store_state_t) <= KV_DATA_MAX && sizeof(store_rk_t) <= KV_DATA_MAX, "record too big for kv");
_Static_assert(sizeof(store_key_t) == KV_KEY_SIZE && STORE_RK_MAX + 1 <= KV_MAX, "kv too small");

static store_state_t state;
static nv_t nv;
/* record keys are keyed, they must not reveal which accounts are stored */
static uint8_t name_key[32];

static void use_master(void)
{
    static const char label[] = "rk name";

    cred_set_master(state.master);
    hmac_sha256(state.master, sizeof(state.master), label, sizeof(label) - 1, name_key);
}

static int new_state(void)
{
    memset(&state, 0, sizeof(state));
    state.magic = STATE_MAGIC;
    state.min_pin_len = 4;
    if (!rng_read(state.master, sizeof(state.master)))
    {
        return -1;
    }
    use_master();
    nv.pin_retries = STORE_PIN_RETRIES;
    if (!nv_save(&nv))
    {
        return -1;
    }
    return store_save_state();
}

int store_init(void)
{
    /* both blank on a new device; one without the other only after a chip erase over SWD */
    if (!nv_load(&nv))
    {
        memset(&nv, 0, sizeof(nv));
        kv_erase_all();
        return new_state();
    }
    if (!kv_read(state_key, &state, sizeof(state)) || state.magic != STATE_MAGIC)
    {
        kv_erase_all();
        return new_state();
    }
    use_master();
    return 0;
}

store_state_t *store_state(void)
{
    return &state;
}

int store_save_state(void)
{
    return kv_write(state_key, &state, sizeof(state)) ? 0 : -1;
}

uint8_t store_pin_retries(void)
{
    return nv.pin_retries;
}

int store_set_pin_retries(uint8_t retries)
{
    if (retries == nv.pin_retries)
    {
        return 0;
    }
    nv.pin_retries = retries;
    return nv_save(&nv) ? 0 : -1;
}

int store_reset(void)
{
    crypto_wipe(&state, sizeof(state));
    if (!kv_erase_all())
    {
        return -1;
    }
    return new_state();
}

uint32_t store_counter_next(void)
{
    nv.counter++;
    nv_save(&nv);
    return nv.counter;
}

store_key_t store_rk_key(const uint8_t rp_id_hash[32], const uint8_t *user_id, size_t user_id_len)
{
    hmac_sha256_ctx_t ctx;
    uint8_t hash[32];
    store_key_t key;

    hmac_sha256_init(&ctx, name_key, sizeof(name_key));
    hmac_sha256_update(&ctx, rp_id_hash, 32);
    hmac_sha256_update(&ctx, user_id, user_id_len);
    hmac_sha256_final(&ctx, hash);
    memcpy(key.b, hash, sizeof(key.b));
    return key;
}

static bool count_cb(const uint8_t key[KV_KEY_SIZE], void *ctx)
{
    if (memcmp(key, state_key, KV_KEY_SIZE) != 0)
    {
        (*(int *)ctx)++;
    }
    return true;
}

int store_rk_count(void)
{
    int n = 0;
    kv_foreach(count_cb, &n);
    return n;
}

bool store_rk_exists(const store_key_t *key)
{
    return kv_exists(key->b);
}

int store_rk_put(store_rk_t *rk)
{
    store_key_t key = store_rk_key(rk->rp_id_hash, rk->user_id, rk->user_id_len);

    if (!kv_exists(key.b) && store_rk_count() >= STORE_RK_MAX)
    {
        return -1;
    }

    /* new record, updates keep their position in the assertion order */
    if (rk->created == 0)
    {
        rk->created = ++state.rk_seq;
        if (store_save_state() < 0)
        {
            return -1;
        }
    }
    return kv_write(key.b, rk, sizeof(*rk)) ? 0 : -1;
}

int store_rk_get(const store_key_t *key, store_rk_t *rk)
{
    if (memcmp(key->b, state_key, KV_KEY_SIZE) == 0)
    {
        return -1;
    }
    return kv_read(key->b, rk, sizeof(*rk)) ? 0 : -1;
}

int store_rk_delete(const store_key_t *key)
{
    return kv_delete(key->b) ? 0 : -1;
}

typedef struct
{
    const uint8_t *cred_id;
    store_key_t *key;
    store_rk_t *rk;
    bool found;
} find_ctx_t;

static bool find_cb(const store_key_t *key, const store_rk_t *rk, void *ctx)
{
    find_ctx_t *f = ctx;

    if (memcmp(rk->cred_id, f->cred_id, CRED_ID_LEN) == 0)
    {
        *f->key = *key;
        if (f->rk)
        {
            memcpy(f->rk, rk, sizeof(*rk));
        }
        f->found = true;
        return false;
    }
    return true;
}

bool store_rk_find_cred(const uint8_t *cred_id, size_t len, store_key_t *key, store_rk_t *rk)
{
    find_ctx_t f = {.cred_id = cred_id, .key = key, .rk = rk, .found = false};

    if (len != CRED_ID_LEN)
    {
        return false;
    }
    store_rk_foreach(find_cb, &f);
    return f.found;
}

bool store_cred_live(const cred_t *c)
{
    store_key_t key;

    /* credential IDs are stateless, only the record of a discoverable one can revoke it */
    return !(c->flags & CRED_FLAG_RK) || store_rk_find_cred(c->id, CRED_ID_LEN, &key, NULL);
}

typedef struct
{
    store_rk_cb_t cb;
    void *ctx;
} foreach_ctx_t;

static bool foreach_cb(const uint8_t kv_key[KV_KEY_SIZE], void *ctx)
{
    static store_rk_t rk;
    foreach_ctx_t *f = ctx;
    store_key_t key;
    bool more;

    memcpy(key.b, kv_key, sizeof(key.b));
    if (store_rk_get(&key, &rk) < 0)
    {
        return true;
    }
    more = f->cb(&key, &rk, f->ctx);
    crypto_wipe(&rk, sizeof(rk));
    return more;
}

int store_rk_foreach(store_rk_cb_t cb, void *ctx)
{
    foreach_ctx_t f = {.cb = cb, .ctx = ctx};

    kv_foreach(foreach_cb, &f);
    return 0;
}
