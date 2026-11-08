#ifndef __GPIO_H__
#define __GPIO_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>

void gpio_init(void);

/* inputs, true while pressed */
bool button(void);      /* OK: PB10, or PA0 on the board */
bool button_next(void); /* Next / cancel: PC14 */

/* outputs */
void led_run(bool on);
void led_toggle(void);

#ifdef __cplusplus
}
#endif
#endif /*__ GPIO_H__ */
