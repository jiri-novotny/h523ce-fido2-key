#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include CMSIS_device_header

#include "iflash.h"

extern void Error_Handler(void);

static volatile bool reading;
static volatile bool ecc_error;

void NMI_Handler(void)
{
    if (reading && (FLASH->ECCDETR & FLASH_ECCR_ECCD))
    {
        FLASH->ECCDETR = FLASH_ECCR_ECCD;
        if (ICACHE->CR & ICACHE_CR_EN)
        {
            ICACHE->CR |= ICACHE_CR_CACHEINV;
        }
        ecc_error = true;
        return;
    }
    Error_Handler();
}

bool iflash_read_qw(uint32_t addr, void *qw)
{
    uint32_t *w = qw;

    ecc_error = false;
    reading = true;
    for (uint32_t i = 0; i < IFLASH_QW_SIZE / sizeof(uint32_t); i++)
    {
        w[i] = ((const volatile uint32_t *)addr)[i];
    }
    __DSB();
    /* the NMI may still be on its way */
    while ((FLASH->ECCDETR & FLASH_ECCR_ECCD) && !ecc_error)
    {
    }
    reading = false;
    return !ecc_error;
}

bool iflash_blank_qw(const void *qw)
{
    const uint32_t *w = qw;

    return (w[0] & w[1] & w[2] & w[3]) == 0xFFFFFFFFU;
}

bool iflash_program_qw(uint32_t addr, const void *qw)
{
    uint8_t check[IFLASH_QW_SIZE];
    bool ok;

    HAL_FLASH_Unlock();
    ok = HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD, addr, (uint32_t)qw) == HAL_OK;
    HAL_FLASH_Lock();
    return ok && iflash_read_qw(addr, check) && memcmp(check, qw, IFLASH_QW_SIZE) == 0;
}

bool iflash_erase_sector(uint32_t addr)
{
    FLASH_EraseInitTypeDef erase = {
        .TypeErase = FLASH_TYPEERASE_SECTORS,
        .Banks = addr < FLASH_BASE + FLASH_BANK_SIZE ? FLASH_BANK_1 : FLASH_BANK_2,
        .Sector = ((addr - FLASH_BASE) % FLASH_BANK_SIZE) / FLASH_SECTOR_SIZE,
        .NbSectors = 1,
    };
    uint32_t err;
    bool ok;

    HAL_FLASH_Unlock();
    ok = HAL_FLASHEx_Erase(&erase, &err) == HAL_OK;
    HAL_FLASH_Lock();
    return ok;
}
