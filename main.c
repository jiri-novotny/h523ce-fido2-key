#include <stdint.h>

#include CMSIS_device_header
#include "monocypher.h"
#include "tusb.h"

#include "clk.h"
#include "cred.h"
#include "ctap2.h"
#include "ctaphid.h"
#include "gpio.h"
#include "kv.h"
#include "obk.h"
#include "rng.h"
#include "store.h"
#include "up.h"
#include "update.h"
#include "usb.h"
#include "watchdog.h"

/* Private user code ---------------------------------------------------------*/

/**
 * @brief  This function is executed in case of error occurrence.
 */
void Error_Handler(void)
{
  __disable_irq();
  led_run(true);
  while (1)
  {
  }
}

void HardFault_Handler(void)
{
  __asm("BKPT #0\n");
}

/* Public user code ---------------------------------------------------------*/

int main(void)
{
  uint32_t blink_timer = 0;
  /* per-device key from OBK, only kv keeps a copy */
  uint8_t device_key[OBK_KEY_SIZE];

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* Configure the system clock */
  SystemClock_Config();

  /* Initialize all configured peripherals */
  watchdog_init();
  gpio_init();
  rng_init();
  if (!obk_load_key(device_key))
  {
    Error_Handler();
  }
  kv_init(device_key);
  crypto_wipe(device_key, sizeof(device_key));
  cred_init();
  if (store_init() != 0)
  {
    Error_Handler();
  }
  ctap2_init();
  ctaphid_init();
  usb_init();
  up_init();

  uint32_t tick = 0;
  uint32_t tick10ms = HAL_GetTick();
  while (1)
  {
    /* run fast */
    tick = HAL_GetTick();
    tud_task(); // tinyusb device task
    ctaphid_task();
    if ((tick - tick10ms) < 10)
    {
      continue;
    }
    tick10ms = tick;

    /* run every 10ms */
    blink_timer++;
    if (up_led_active())
    {
      /* user presence / wink indication owns the LED */
    }
    else if (blink_timer == 1)
    {
      led_run(true);
    }
    else if (blink_timer == 2)
    {
      led_run(false);
    }
    if (blink_timer == 100)
    {
      blink_timer = 0;
      WDI();
    }

    if (should_reset())
    {
      NVIC_SystemReset();
    }
  }
}
