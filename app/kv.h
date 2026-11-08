#ifndef __KV_H__
#define __KV_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KV_SIZE     0x10000U /* first part of the app data area (BOOT_DATA_BASE), nv.c has the rest */
#define KV_KEY_SIZE 8U
#define KV_DATA_MAX 424U /* largest record */
#define KV_MAX      96U  /* records, the rest of the 128 slots keeps compaction going */

/*
 * Record store in internal flash, encrypted per record (XChaCha20-Poly1305) with the device key
 * and the record key as associated data. A write goes to a new slot before the old copy is
 * marked dead, so a power loss keeps either the old or the new record.
 */

/* scans the area, finishes a write or compaction cut short; keeps a copy of the device key */
void kv_init(const uint8_t key[32]);

/* reads up to len bytes of the record, false if there is none */
bool kv_read(const uint8_t key[KV_KEY_SIZE], void *buf, size_t len);

bool kv_exists(const uint8_t key[KV_KEY_SIZE]);

/* creates or replaces a record of len <= KV_DATA_MAX bytes */
bool kv_write(const uint8_t key[KV_KEY_SIZE], const void *data, size_t len);

bool kv_delete(const uint8_t key[KV_KEY_SIZE]);

/* erases every record */
bool kv_erase_all(void);

/* calls cb with the key of every record, cb returns false to stop; the store must not change */
typedef bool (*kv_cb_t)(const uint8_t key[KV_KEY_SIZE], void *ctx);
void kv_foreach(kv_cb_t cb, void *ctx);

#ifdef __cplusplus
}
#endif
#endif /* __KV_H__ */
