#ifndef __STORE_H__
#define __STORE_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cred.h"

#define STORE_RK_MAX       64
#define STORE_RP_ID_MAX    128
#define STORE_USER_ID_MAX  64
#define STORE_USER_STR_MAX 64

#define STORE_PIN_RETRIES 8

/* short record key derived from rpIdHash | user id, same account overwrites */
typedef struct
{
    uint8_t b[8];
} store_key_t;

typedef struct
{
    uint32_t magic;
    uint8_t master[32];
    uint8_t pin_set;
    uint8_t min_pin_len;
    uint8_t pin_hash[16];
    uint32_t rk_seq; /* creation order of discoverable credentials */
} store_state_t;

/* discoverable credential, kv record of its store_key_t */
typedef struct
{
    uint8_t cred_id[CRED_ID_LEN];
    uint8_t rp_id_hash[32];
    uint32_t created;
    uint8_t rp_id_len;
    uint8_t user_id_len;
    uint8_t user_name_len;
    uint8_t display_name_len;
    char rp_id[STORE_RP_ID_MAX];
    uint8_t user_id[STORE_USER_ID_MAX];
    char user_name[STORE_USER_STR_MAX];
    char display_name[STORE_USER_STR_MAX];
} store_rk_t;

int store_init(void);
store_state_t *store_state(void);
int store_save_state(void);
int store_reset(void);

/* PIN retries, in nv.h: one 16-byte write per attempt */
uint8_t store_pin_retries(void);
int store_set_pin_retries(uint8_t retries);

/* signature counter, returns new value; never goes back, not even on reset */
uint32_t store_counter_next(void);

store_key_t store_rk_key(const uint8_t rp_id_hash[32], const uint8_t *user_id, size_t user_id_len);
int store_rk_count(void);
bool store_rk_exists(const store_key_t *key);
int store_rk_put(store_rk_t *rk);
int store_rk_get(const store_key_t *key, store_rk_t *rk);
int store_rk_delete(const store_key_t *key);
bool store_rk_find_cred(const uint8_t *cred_id, size_t len, store_key_t *key, store_rk_t *rk);
/* false for a discoverable credential whose record was deleted or replaced: its ID is revoked */
bool store_cred_live(const cred_t *c);

/* iterate all records, callback returns false to stop */
typedef bool (*store_rk_cb_t)(const store_key_t *key, const store_rk_t *rk, void *ctx);
int store_rk_foreach(store_rk_cb_t cb, void *ctx);

#ifdef __cplusplus
}
#endif
#endif /* __STORE_H__ */
