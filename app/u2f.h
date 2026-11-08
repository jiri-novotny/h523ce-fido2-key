#ifndef __U2F_H__
#define __U2F_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

/* CTAP1 / U2F raw messages over CTAPHID_MSG, returns response length including status word */
size_t u2f_process(const uint8_t *req, size_t len, uint8_t *resp, size_t cap);
void u2f_tick(void);
void u2f_reset(void); /* attestation key changed */

#ifdef __cplusplus
}
#endif
#endif /* __U2F_H__ */
