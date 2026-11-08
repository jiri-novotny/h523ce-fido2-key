#ifndef __USB_DFU_H__
#define __USB_DFU_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>

#include <stdint.h>

/* true once a downloaded image is verified and installed, the bootloader then resets */
bool dfu_done(void);

/* call often: the button confirms the image waiting in block 0 */
void dfu_task(void);
bool dfu_confirming(void);

/* version of the verified app in the slot, 0 if none */
uint32_t dfu_installed_version(void);

#ifdef __cplusplus
}
#endif
#endif /* __USB_DFU_H__ */
