#ifndef __IFLASH_H__
#define __IFLASH_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

#define IFLASH_QW_SIZE 16U /* flash is programmed by 128-bit quad-words, once between erases */

/*
 * Internal flash access for the app data area (BOOT_DATA_BASE). Programming cut short by a
 * power loss can leave a quad-word with an ECC double error; reading it raises an NMI, which
 * is ignored while these functions read and reported as a failed read.
 */

/* false on an ECC double error */
bool iflash_read_qw(uint32_t addr, void *qw);

bool iflash_blank_qw(const void *qw);

/* programs a blank quad-word and reads it back */
bool iflash_program_qw(uint32_t addr, const void *qw);

/* erases the 8 KB sector at addr */
bool iflash_erase_sector(uint32_t addr);

#ifdef __cplusplus
}
#endif
#endif /* __IFLASH_H__ */
