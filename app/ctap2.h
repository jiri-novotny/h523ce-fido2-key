#ifndef __CTAP2_H__
#define __CTAP2_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

void ctap2_init(void);

/* CTAPHID_CBOR payload, returns response length (status byte + CBOR) */
size_t ctap2_process(const uint8_t *req, size_t len, uint8_t *resp, size_t cap);

/* waits for OK with keepalives, returns CTAP2 status (0 = touched, Next = operation denied) */
uint8_t ctap2_wait_up(void);

#ifdef __cplusplus
}
#endif
#endif /* __CTAP2_H__ */
