#ifndef TUSB_CONFIG_H_
#define TUSB_CONFIG_H_

#ifdef __cplusplus
 extern "C" {
#endif

#ifndef CFG_TUSB_MCU
#error CFG_TUSB_MCU must be defined
#endif

#define CFG_TUSB_OS               OPT_OS_NONE
#define CFG_TUSB_DEBUG            0
#define CFG_TUSB_MEM_SECTION
#define CFG_TUSB_MEM_ALIGN        __attribute__ ((aligned(4)))

#define CFG_TUD_ENABLED           1
#define CFG_TUD_MAX_SPEED         OPT_MODE_DEFAULT_SPEED
#define CFG_TUD_ENDPOINT0_SIZE    64

/* bootloader: USB DFU 1.1, download only */
#define CFG_TUD_DFU               1
#define CFG_TUD_DFU_XFER_BUFSIZE  1024 /* multiple of the 16 B flash programming unit */

#ifdef __cplusplus
 }
#endif

#endif /* TUSB_CONFIG_H_ */
