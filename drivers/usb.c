/* Includes ------------------------------------------------------------------*/
#include "stm32h5xx_ll_bus.h"
#include "stm32h5xx_ll_rcc.h"

#include "tusb.h"

void usb_init(void)
{
  tusb_rhport_init_t dev_init = {.role = TUSB_ROLE_DEVICE, .speed = TUSB_SPEED_AUTO};

  LL_RCC_SetUSBClockSource(LL_RCC_USB_CLKSOURCE_HSI48);
  LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_USB);

#if defined (PWR_USBSCR_USB33DEN)
  /* Enable VDDUSB */
  HAL_PWREx_EnableVddUSB();
#endif

  tusb_init(0, &dev_init);
}

void USB_DRD_FS_IRQHandler(void)
{
  tud_int_handler(0);
}
