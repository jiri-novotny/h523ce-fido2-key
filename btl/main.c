#include <stdbool.h>
#include <stdint.h>

#include CMSIS_device_header
#include "stm32h5xx_ll_bus.h"
#include "stm32h5xx_ll_system.h"
#include "tusb.h"

#include "boot.h"
#include "clk.h"
#include "gpio.h"
#include "image.h"
#include "rng.h"
#include "ui.h"
#include "usb.h"
#include "usb_dfu.h"
#include "watchdog.h"

#define LED_DFU_MS      250 /* slow blink in DFU mode */
#define LED_CONFIRM_MS  100 /* fast blink while an update waits for the button */
#define RESET_DELAY_MS  2500 /* dfu-util waits 1 s in dfuMANIFEST before it reads the final status */

typedef void (*entry_t)(void);

void Error_Handler(void)
{
  NVIC_SystemReset();
}

void HardFault_Handler(void)
{
  NVIC_SystemReset();
}

/*
 * Jump to the verified app: HDPL raised to 2 so the app can't touch the bootloader's OBK area
 * (rollback counter), peripherals and clocks back to reset state, then the app's vectors.
 */
static void start_app(void)
{
  const volatile uint32_t *vectors = (const volatile uint32_t *)BOOT_APP_BASE;

  __disable_irq();

  /* leave HDPL1 first, the deinit below doesn't reset the SBS (APB3 reset mask) */
  LL_APB3_GRP1_EnableClock(LL_APB3_GRP1_PERIPH_SBS);
  LL_SBS_IncrementHDPLValue();

  SysTick->CTRL = 0;
  for (uint32_t i = 0; i < sizeof(NVIC->ICER) / sizeof(NVIC->ICER[0]); i++)
  {
    NVIC->ICER[i] = 0xFFFFFFFFU;
    NVIC->ICPR[i] = 0xFFFFFFFFU;
  }
  HAL_RCC_DeInit();
  HAL_DeInit();

  /* VTOR is set by the app's SystemInit() (VECT_TAB_OFFSET) */
  __set_MSPLIM(0);
  __set_MSP(vectors[0]);
  __DSB();
  __ISB();
  __enable_irq();
  ((entry_t)vectors[1])();
}

int main(void)
{
  /* stay in DFU on request of the app (CTAPHID vendor command) or with OK held at reset */
  bool request = BOOT_REQUEST == BOOT_REQUEST_MAGIC;
  uint32_t blink = 0;
  uint32_t done_at = 0;

  BOOT_REQUEST = 0;

  HAL_Init();
  SystemClock_Config();
  watchdog_init();
  gpio_init();
  rng_init(); /* the PKA needs the RNG */
  HAL_Delay(2); /* button pull-ups */

  if (!request && !button() && image_slot_ok())
  {
    start_app();
  }

  /* no valid image, or update requested */
  ui_init();
  ui_waiting(dfu_installed_version(), rollback_min());
  usb_init();
  while (1)
  {
    uint32_t tick = HAL_GetTick();

    tud_task();
    dfu_task();
    WDI();

    if ((tick - blink) >= (dfu_confirming() ? LED_CONFIRM_MS : LED_DFU_MS))
    {
      blink = tick;
      led_toggle();
    }

    if (dfu_done())
    {
      if (done_at == 0)
      {
        done_at = tick | 1U;
      }
      else if ((tick - done_at) >= RESET_DELAY_MS)
      {
        NVIC_SystemReset();
      }
    }
  }
}
