#ifndef __NV_H__
#define __NV_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

/*
 * Small state written often, in a ring of internal flash sectors after the record store (kv.h):
 * one 16-byte record per change.
 */
typedef struct
{
    uint32_t counter; /* signature counter */
    uint8_t pin_retries;
    uint8_t reserved[7];
} nv_t;

/* latest saved record, false if the area is blank */
bool nv_load(nv_t *nv);

/* appends a record, power loss keeps the previous one */
bool nv_save(const nv_t *nv);

#ifdef __cplusplus
}
#endif
#endif /* __NV_H__ */
