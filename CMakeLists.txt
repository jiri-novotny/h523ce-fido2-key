cmake_minimum_required(VERSION 3.12)

# Setup compiler settings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(stm32h523-fido2 C ASM)

message("-- Build type: " ${CMAKE_BUILD_TYPE})

# Project-specific
add_definitions(-DUSE_HAL_DRIVER)
add_definitions(-DUSE_FULL_LL_DRIVER)
# micro-ecc: P-256 only (ES256, CTAP2 key agreement)
add_definitions(-DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 -DuECC_SUPPORTS_secp224r1=0 -DuECC_SUPPORTS_secp256k1=0)
add_definitions(-DuECC_OPTIMIZATION_LEVEL=3 -DuECC_SQUARE_FUNC=1)

include_directories(drivers)
include_directories(lib/cmsis-core/CMSIS/Core/Include)
include_directories(lib/micro-ecc)
include_directories(lib/monocypher/src)
include_directories(lib/monocypher/src/optional)
include_directories(lib/tinyusb/src)

# target selected by -Dapp=1 or -Dbtl=1 (VS Code configuration name), both STM32H523
if(app OR btl)
  set(CPU_CORE cortex-m33)

  add_definitions(-DCMSIS_device_header="stm32h5xx.h")
  add_definitions(-DSTM32H523xx)
  # tinyusb
  add_definitions(-DCFG_TUSB_MCU=OPT_MCU_STM32H5)

  include_directories(drivers)
  include_directories(lib/cmsis-device-h5/Include)
  include_directories(lib/stm32h5xx-hal-driver/Inc)

  add_subdirectory(drivers)
else()
  message(FATAL_ERROR "Please select target: -Dapp=1 or -Dbtl=1")
endif()

# Firmware signing, see tools/sign.py and drivers/boot.h
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(SIGN_TOOL ${CMAKE_CURRENT_SOURCE_DIR}/tools/sign.py)
set(SIGN_KEY ${CMAKE_CURRENT_SOURCE_DIR}/tools/keys/dev_signing_key.pem CACHE FILEPATH "ECDSA P-256 firmware signing key")
set(FW_VERSION 2 CACHE STRING "App firmware version, the bootloader refuses versions below the last installed one")
if(NOT EXISTS ${SIGN_KEY})
  message(WARNING "No signing key, generating a development key ${SIGN_KEY}")
  execute_process(COMMAND ${Python3_EXECUTABLE} ${SIGN_TOOL} keygen ${SIGN_KEY} COMMAND_ERROR_IS_FATAL ANY)
endif()

add_subdirectory(lib)

if(app)
  set(EXE_NAME ${PROJECT_NAME})
  set(linker_script_SRC ${CMAKE_CURRENT_SOURCE_DIR}/app/STM32H523xx_FLASH.ld)

  include_directories(app)
  add_subdirectory(app)

  set(SOURCE ${SOURCE} main.c)
elseif(btl)
  set(EXE_NAME ${PROJECT_NAME}-btl)
  set(linker_script_SRC ${CMAKE_CURRENT_SOURCE_DIR}/btl/STM32H523xx_FLASH.ld)

  include_directories(btl ${CMAKE_CURRENT_BINARY_DIR})
  add_subdirectory(btl)

  # public half of the signing key, built into the bootloader
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/btl_pubkey.h
    COMMAND ${Python3_EXECUTABLE} ${SIGN_TOOL} pubkey ${SIGN_KEY} ${CMAKE_CURRENT_BINARY_DIR}/btl_pubkey.h
    DEPENDS ${SIGN_KEY} ${SIGN_TOOL}
  )
  set(SOURCE ${SOURCE} ${CMAKE_CURRENT_BINARY_DIR}/btl_pubkey.h)
endif()

# Executable files
add_executable(${EXE_NAME} syscalls.c ${SOURCE})

if(app)
  # the app runs from the slot behind the bootloader and the image header (drivers/boot.h)
  target_compile_definitions(${EXE_NAME} PRIVATE VECT_TAB_OFFSET=0x8400U)
endif()

target_compile_options(${EXE_NAME} PRIVATE
    -mcpu=${CPU_CORE}
    $<$<CONFIG:Debug>:-Og -g3>
    $<$<CONFIG:MinSizeRel>:-Os>
    $<$<CONFIG:Release>:-O3>
    -ffunction-sections -fdata-sections
    -Wall
    -Wextra
    -Werror
    -Wno-unused-parameter
    -fstack-usage -fcyclomatic-complexity
    --specs=nano.specs -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb
)


# Linker options
target_link_options(${EXE_NAME} PRIVATE
    -mcpu=${CPU_CORE}
    -T${linker_script_SRC}
    --specs=nosys.specs
    -Wl,-Map=${EXE_NAME}.map
    -Wl,--gc-sections -static
    -Wl,--print-memory-usage
    --specs=nano.specs -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb
    -Wl,--start-group -lc -lm -Wl,--end-group
)

# Execute post-build to print size, generate hex and bin
add_custom_command(TARGET ${EXE_NAME} POST_BUILD
    COMMAND "echo"
    COMMAND ${CMAKE_SIZE} $<TARGET_FILE:${EXE_NAME}>
    COMMAND ${CMAKE_OBJCOPY} -O ihex $<TARGET_FILE:${EXE_NAME}> ${EXE_NAME}.hex
    COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:${EXE_NAME}> ${EXE_NAME}.bin
)

if(app)
  # signed slot image for the bootloader: .bin for USB DFU, .hex for SWD
  add_custom_command(TARGET ${EXE_NAME} POST_BUILD
    COMMAND ${Python3_EXECUTABLE} ${SIGN_TOOL} sign ${SIGN_KEY} ${EXE_NAME}.bin ${FW_VERSION} ${EXE_NAME}-signed
  )
endif()
