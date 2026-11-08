#ifndef __WATCHDOG_H__
#define __WATCHDOG_H__

#ifdef __cplusplus
extern "C"
{
#endif

/* Includes ------------------------------------------------------------------*/
#include <stdint.h>

void watchdog_init(void);
void watchdog_reinit(uint16_t time);
void watchdog_state(void);
void WDI(void);

#ifdef __cplusplus
}
#endif
#endif /* __WATCHDOG_H__ */
