#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include CMSIS_device_header

#include "stm32h5xx_ll_bus.h"

#include "rng.h"

#include "obk.h"

#define OBK_MAGIC     0x44564B31U /* "DVK1" */
#define OBK_SLOT_SIZE (OBK_KEY_SIZE + OBK_QW_SIZE)
/* HDPL1 belongs to the bootloader, the app starts at HDPL2 and keeps its key there */
#define OBK_BASE      FLASH_OBK_HDPL2_BASE_NS
#define OBK_SLOTS     (FLASH_OBK_HDPL2_SIZE / OBK_SLOT_SIZE)

/*
 * Slot = key followed by a commit quad-word, written last. A slot left partially written
 * by a power loss can't be reprogrammed in the current sector, the next blank one is used.
 * The key never changes, so the alternate sector / swap procedure is not needed.
 */
typedef struct
{
    uint8_t key[OBK_KEY_SIZE];
    uint32_t magic;
    uint32_t inv_magic;
    uint32_t reserved[2];
} obk_slot_t;

static const volatile obk_slot_t *slot_addr(uint32_t i)
{
    return (const volatile obk_slot_t *)(OBK_BASE + i * OBK_SLOT_SIZE);
}

static bool slot_valid(const volatile obk_slot_t *s)
{
    return s->magic == OBK_MAGIC && s->inv_magic == ~OBK_MAGIC;
}

bool obk_blank(uint32_t addr, uint32_t len)
{
    const volatile uint32_t *w = (const volatile uint32_t *)addr;

    for (uint32_t i = 0; i < len / sizeof(uint32_t); i++)
    {
        if (w[i] != 0xFFFFFFFFU)
        {
            return false;
        }
    }
    return true;
}

bool obk_program(uint32_t addr, const void *data, uint32_t len)
{
    bool ok = HAL_FLASH_Unlock() == HAL_OK && HAL_FLASHEx_OBK_Unlock() == HAL_OK;

    for (uint32_t off = 0; ok && off < len; off += OBK_QW_SIZE)
    {
        ok = HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD_OBK, addr + off, (uint32_t)data + off) == HAL_OK;
    }

    HAL_FLASHEx_OBK_Lock();
    HAL_FLASH_Lock();
    return ok;
}

uint32_t obk_hdpl(void)
{
    LL_APB3_GRP1_EnableClock(LL_APB3_GRP1_PERIPH_SBS);
    return HAL_SBS_GetHDPLValue();
}

static bool provision(const volatile obk_slot_t *s)
{
    obk_slot_t data = {.magic = OBK_MAGIC, .inv_magic = ~OBK_MAGIC, .reserved = {0xFFFFFFFFU, 0xFFFFFFFFU}};
    bool ok = rng_read(data.key, sizeof(data.key)) && obk_program((uint32_t)s, &data, sizeof(data));

    memset(&data, 0, sizeof(data));
    return ok;
}

bool obk_load_key(uint8_t key[OBK_KEY_SIZE])
{
    bool ok = false;

    if (obk_hdpl() != SBS_HDPL_VALUE_2)
    {
        return false;
    }

    for (uint32_t i = 0; i < OBK_SLOTS; i++)
    {
        const volatile obk_slot_t *s = slot_addr(i);

        if (obk_blank((uint32_t)s, OBK_SLOT_SIZE) && !provision(s))
        {
            /* nothing written (RNG or flash error): the next boot would provision this slot
               again and get a different key than a later slot used now, so stop instead */
            if (obk_blank((uint32_t)s, OBK_SLOT_SIZE))
            {
                break;
            }
            continue;
        }
        if (slot_valid(s))
        {
            for (uint32_t j = 0; j < OBK_KEY_SIZE; j++)
            {
                key[j] = s->key[j];
            }
            ok = true;
            break;
        }
    }

    /* hide the area until reset, also when no key was found */
    HAL_SBS_IncrementHDPLValue();
    return ok;
}
