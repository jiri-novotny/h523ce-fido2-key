#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include CMSIS_device_header

#include "stm32h5xx_ll_bus.h"
#include "stm32h5xx_ll_rcc.h"

#include "rng.h"

#define RNG_TIMEOUT_MS  10
#define RNG_RETRIES     3

/* NIST SP 800-90B compliant configuration, same sequence as HAL_RNG_Init() */
static void rng_configure(void)
{
    RNG->CR = RNG_CR_NIST_VALUE | RNG_CR_CONDRST; /* clock error detection enabled (CED = 0) */
    RNG->HTCR = RNG_HTCR_NIST_VALUE;
    RNG->CR &= ~RNG_CR_CONDRST;
    while (RNG->CR & RNG_CR_CONDRST)
    {
    }
    RNG->CR |= RNG_CR_RNGEN;
}

void rng_init(void)
{
    /* HSI48 is enabled in SystemClock_Config() */
    LL_RCC_SetRNGClockSource(LL_RCC_RNG_CLKSOURCE_HSI48);
    LL_AHB2_GRP1_EnableClock(LL_AHB2_GRP1_PERIPH_RNG);
    rng_configure();
}

static bool rng_word(uint32_t *word)
{
    for (int retry = 0; retry < RNG_RETRIES; retry++)
    {
        uint32_t start = HAL_GetTick();

        while (!(RNG->SR & RNG_SR_DRDY))
        {
            if (RNG->SR & (RNG_SR_SECS | RNG_SR_CECS) || (HAL_GetTick() - start) > RNG_TIMEOUT_MS)
            {
                break;
            }
        }

        if ((RNG->SR & (RNG_SR_DRDY | RNG_SR_SECS | RNG_SR_CECS)) == RNG_SR_DRDY)
        {
            *word = RNG->DR;
            /* DR reads 0 when a seed error occurred after DRDY was set */
            if (*word != 0 || !(RNG->SR & RNG_SR_SEIS))
            {
                return true;
            }
        }

        /* seed or clock error - recover with conditioning reset */
        RNG->SR = 0;
        rng_configure();
    }
    return false;
}

/* fills buf with true random data, false on hardware failure (buf must not be used) */
bool rng_read(uint8_t *buf, size_t len)
{
    uint32_t word;

    while (len > 0)
    {
        size_t n = len < sizeof(word) ? len : sizeof(word);

        if (!rng_word(&word))
        {
            return false;
        }
        memcpy(buf, &word, n);
        buf += n;
        len -= n;
    }
    word = 0;
    return true;
}
