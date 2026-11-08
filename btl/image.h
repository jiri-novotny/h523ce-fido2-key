#ifndef __IMAGE_H__
#define __IMAGE_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

#include "boot.h"

/* header fields, version against the rollback counter and the signature, run before erasing */
bool image_header_ok(const boot_hdr_t *hdr);

/* full check of the image in the slot: header as above plus the image hash */
bool image_slot_ok(void);

/* lowest firmware version still allowed to boot, 0 when never set */
uint32_t rollback_min(void);

/* raises the stored minimum to version, no-op if not higher */
bool rollback_raise(uint32_t version);

#ifdef __cplusplus
}
#endif
#endif /* __IMAGE_H__ */
