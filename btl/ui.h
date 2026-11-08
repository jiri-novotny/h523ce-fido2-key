#ifndef __UI_H__
#define __UI_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

/* bootloader screens on the display, all no-ops without one; version 0 = no valid firmware */

void ui_init(void);
void ui_waiting(uint32_t installed, uint32_t min_version);
void ui_confirm(uint32_t version, uint32_t installed);
void ui_progress(uint32_t version, uint32_t percent);
void ui_message(const char *line0, const char *line1, const char *line2);

#ifdef __cplusplus
}
#endif
#endif /* __UI_H__ */
