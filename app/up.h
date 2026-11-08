#ifndef __UP_H__
#define __UP_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* user presence - OK and Next buttons, LED feedback on PC13, prompts on the display */

void up_init(void);            /* display: boot screen for a few seconds */
void up_tick(void);            /* call often: button debounce and LED patterns */
uint32_t up_press_count(void); /* incremented on every debounced press of OK */
uint32_t up_next_count(void);  /* the same for Next */
void up_set_waiting(bool on);  /* fast blink and the prompt while waiting for touch */

/*
 * What the next touch confirms, shown from up_set_waiting(true) until the wait ends. The site
 * (rpId) is shown as ASCII, keeping its end when too long, anything else as '?'. The account is
 * UTF-8, Latin letters lose their accents. Site and account may be NULL.
 */
void up_prompt(const char *action, const void *site, size_t site_len, const void *account, size_t account_len);
/* the same with fixed texts */
void up_prompt_text(const char *action, const char *line1, const char *line2);
/* bottom line of the next prompts until the wait ends, "OK: confirm  Next: cancel" by default */
void up_hint(const char *text);
void up_wink(void);            /* CTAPHID_WINK */
bool up_led_active(void);      /* LED is driven by this module */

#ifdef __cplusplus
}
#endif
#endif /* __UP_H__ */
