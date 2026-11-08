set(SOURCE
   ${SOURCE}

   ${CMAKE_CURRENT_SOURCE_DIR}/tinyusb/src/common/tusb_fifo.c
   ${CMAKE_CURRENT_SOURCE_DIR}/tinyusb/src/device/usbd.c
   ${CMAKE_CURRENT_SOURCE_DIR}/tinyusb/src/portable/st/stm32_fsdev/dcd_stm32_fsdev.c
   ${CMAKE_CURRENT_SOURCE_DIR}/tinyusb/src/portable/st/stm32_fsdev/fsdev_common.c
   ${CMAKE_CURRENT_SOURCE_DIR}/tinyusb/src/tusb.c
)

if(app)
  set(SOURCE
     ${SOURCE}

     ${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc/uECC.c

     ${CMAKE_CURRENT_SOURCE_DIR}/monocypher/src/monocypher.c
     ${CMAKE_CURRENT_SOURCE_DIR}/monocypher/src/optional/monocypher-ed25519.c

     ${CMAKE_CURRENT_SOURCE_DIR}/tinyusb/src/class/hid/hid_device.c
  )
elseif(btl)
  set(SOURCE
     ${SOURCE}

     ${CMAKE_CURRENT_SOURCE_DIR}/tinyusb/src/class/dfu/dfu_device.c
  )
endif()

set(SOURCE ${SOURCE} PARENT_SCOPE)
