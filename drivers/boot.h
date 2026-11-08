#ifndef __BOOT_H__
#define __BOOT_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

/*
 * Flash layout shared by the bootloader (btl), the application (app) and tools/sign.py.
 *
 *   0x08000000  bootloader, BOOT_BTL_SIZE, write-protected in production
 *   0x08008000  application slot: boot_hdr_t padded to BOOT_HDR_SIZE, then the app image
 *   0x08008400  application vector table (VECT_TAB_OFFSET of the app)
 *   0x08068000  app data, BOOT_DATA_SIZE, never erased by the bootloader:
 *               64 KB records (state, credentials), 32 KB PIN retries and signature counter
 */
#define BOOT_FLASH_BASE 0x08000000U
#define BOOT_FLASH_SIZE 0x00080000U
#define BOOT_BTL_SIZE   0x00008000U /* _Btl_Size in both linker scripts */
#define BOOT_SLOT_BASE  (BOOT_FLASH_BASE + BOOT_BTL_SIZE)
#define BOOT_DATA_SIZE  0x00018000U /* _Data_Size in both linker scripts, twelve sectors at the end of bank 2 */
#define BOOT_DATA_BASE  (BOOT_FLASH_BASE + BOOT_FLASH_SIZE - BOOT_DATA_SIZE)
#define BOOT_SLOT_SIZE  (BOOT_FLASH_SIZE - BOOT_BTL_SIZE - BOOT_DATA_SIZE)
#define BOOT_HDR_SIZE   0x400U /* app vector table is 149 entries (0x254 B), VTOR needs 1 KB alignment */
#define BOOT_APP_BASE   (BOOT_SLOT_BASE + BOOT_HDR_SIZE)
#define BOOT_APP_MAX    (BOOT_SLOT_SIZE - BOOT_HDR_SIZE)

#define BOOT_HDR_MAGIC   0x4B464942U /* "BIFK" */
#define BOOT_HDR_VERSION 1U

/*
 * Image header, little endian. The signature is ECDSA P-256 (SHA-256) over the first
 * BOOT_HDR_SIGNED bytes, which include the SHA-256 of the image.
 */
typedef struct
{
    uint32_t magic;
    uint32_t hdr_version;
    uint32_t fw_version; /* anti-rollback: never lower than the last installed version */
    uint32_t image_size; /* bytes following the header, multiple of 16 */
    uint8_t image_sha256[32];
    uint8_t reserved[16];
    uint8_t sig_r[32]; /* big endian */
    uint8_t sig_s[32];
} boot_hdr_t;

#define BOOT_HDR_SIGNED 64U

/*
 * Request to stay in the bootloader, written by the app before a reset. The first 16 bytes
 * of SRAM1 are left out of RAM in both linker scripts and survive a system reset.
 */
#define BOOT_REQUEST       (*(volatile uint32_t *)0x20000000U)
#define BOOT_REQUEST_MAGIC 0xB00710ADU

#ifdef __cplusplus
}
#endif
#endif /* __BOOT_H__ */
