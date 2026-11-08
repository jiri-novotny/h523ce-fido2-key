#ifndef __CTAPHID_H__
#define __CTAPHID_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

#define CTAPHID_PACKET_SIZE 64
#define CTAPHID_MAX_MSG     7609 /* 64 - 7 + 128 * (64 - 5) */

#define CTAPHID_STATUS_PROCESSING 1
#define CTAPHID_STATUS_UPNEEDED   2

void ctaphid_init(void);
void ctaphid_rx(const uint8_t *pkt, uint16_t len); /* from USB OUT endpoint */
void ctaphid_task(void);                           /* from main loop */

/* for long operations: runs USB, sends keepalive, returns true if the host cancelled */
bool ctaphid_poll(uint8_t status);

#ifdef __cplusplus
}
#endif
#endif /* __CTAPHID_H__ */
