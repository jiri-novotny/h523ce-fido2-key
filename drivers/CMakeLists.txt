set(SOURCE
   ${SOURCE}
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/cmsis-device-h5/Source/Templates/gcc/startup_stm32h523xx.s
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/cmsis-device-h5/Source/Templates/system_stm32h5xx.c

   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_hal_cortex.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_hal_dma.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_hal_flash_ex.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_hal_flash.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_hal_hash.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_hal_pcd_ex.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_hal_pcd.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_hal_pka.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_hal_pwr_ex.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_hal_rcc.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_hal.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_ll_dma.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_ll_exti.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_ll_gpio.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_ll_icache.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_ll_rcc.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_ll_spi.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_ll_usb.c
   ${CMAKE_CURRENT_SOURCE_DIR}/../lib/stm32h5xx-hal-driver/Src/stm32h5xx_ll_utils.c

   ${CMAKE_CURRENT_SOURCE_DIR}/clk.c
   ${CMAKE_CURRENT_SOURCE_DIR}/display.c
   ${CMAKE_CURRENT_SOURCE_DIR}/gpio.c
   ${CMAKE_CURRENT_SOURCE_DIR}/obk.c
   ${CMAKE_CURRENT_SOURCE_DIR}/rng.c
   ${CMAKE_CURRENT_SOURCE_DIR}/usb.c
   ${CMAKE_CURRENT_SOURCE_DIR}/watchdog.c

   PARENT_SCOPE
)
