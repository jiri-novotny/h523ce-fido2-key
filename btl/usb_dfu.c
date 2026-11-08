#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include CMSIS_device_header
#include "tusb.h"

#include "boot.h"
#include "gpio.h"
#include "image.h"
#include "ui.h"

#include "usb_dfu.h"

/*
 * USB DFU 1.1, download only (no upload, the app can't be read back). The image is written
 * to the slot block by block, the header is checked - signature and anti-rollback included -
 * before the first sector is erased, the image hash after the last block (manifestation).
 *
 * The first block stays busy (dfuDNBUSY, the host keeps polling) until the user presses OK
 * to install the version shown on the display; Next or no press refuses it.
 */

#define DFU_POLL_MS     10
#define DFU_MANIFEST_MS 200
#define CONFIRM_MS      30000
#define PRESS_MS        30 /* debounce */

static struct
{
    boot_hdr_t hdr;
    bool hdr_ok;
    uint32_t total;     /* header area + image */
    uint32_t written;   /* bytes programmed from the slot start */
    uint32_t erased;    /* slot bytes erased */
    bool done;          /* image verified, reset into it */
    uint32_t shown;     /* progress shown, percent */
} dl;

/* a press must start after the prompt, not be a button held since reset */
typedef struct
{
    bool released;
    uint32_t down;
} press_t;

/* block 0 waiting for OK, Next cancels */
static struct
{
    bool pending;
    uint16_t len;
    uint32_t start;
    press_t ok;
    press_t next;
} confirm;

static uint8_t prog_buf[CFG_TUD_DFU_XFER_BUFSIZE] __attribute__((aligned(4)));

//--------------------------------------------------------------------+
// Flash
//--------------------------------------------------------------------+

static bool flash_erase_sector(uint32_t addr)
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

static bool flash_program(uint32_t addr, const uint8_t *data, uint32_t len)
{
    bool ok = true;

    HAL_FLASH_Unlock();
    for (uint32_t off = 0; ok && off < len; off += 16)
    {
        ok = HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD, addr + off, (uint32_t)&data[off]) == HAL_OK;
    }
    HAL_FLASH_Lock();
    return ok && memcmp((const void *)addr, data, len) == 0;
}

uint32_t dfu_installed_version(void)
{
    return image_slot_ok() ? ((const boot_hdr_t *)BOOT_SLOT_BASE)->fw_version : 0;
}

/* block 0: wrong key, wrong format or older than the rollback counter, the current app stays */
static uint8_t check_header(uint8_t const *data, uint16_t length)
{
    boot_hdr_t hdr;

    memset(&dl, 0, sizeof(dl));
    if (length < sizeof(boot_hdr_t))
    {
        ui_message("Update refused", "Not a firmware image", NULL);
        return DFU_STATUS_ERR_FILE;
    }
    /* checked in a copy, dl only ever holds a verified header */
    memcpy(&hdr, data, sizeof(hdr));
    if (!image_header_ok(&hdr))
    {
        if (hdr.magic == BOOT_HDR_MAGIC && hdr.fw_version < rollback_min())
        {
            ui_message("Update refused", "Older than the oldest", "allowed version");
        }
        else
        {
            ui_message("Update refused", "Not signed with our key", "or not a valid image");
        }
        return DFU_STATUS_ERR_FILE;
    }
    dl.hdr = hdr;
    dl.total = BOOT_HDR_SIZE + hdr.image_size;
    return DFU_STATUS_OK;
}

static uint8_t download(uint16_t block_num, uint8_t const *data, uint16_t length)
{
    uint32_t offset = (uint32_t)block_num * CFG_TUD_DFU_XFER_BUFSIZE;
    uint32_t padded = (length + 15U) & ~15U;
    uint32_t percent;

    if (!dl.hdr_ok || offset != dl.written || offset + length > dl.total)
    {
        return DFU_STATUS_ERR_ADDRESS;
    }

    while (dl.erased < offset + padded)
    {
        if (!flash_erase_sector(BOOT_SLOT_BASE + dl.erased))
        {
            return DFU_STATUS_ERR_ERASE;
        }
        dl.erased += FLASH_SECTOR_SIZE;
    }

    if (data != prog_buf)
    {
        memcpy(prog_buf, data, length);
    }
    memset(prog_buf + length, 0xFF, padded - length);
    if (!flash_program(BOOT_SLOT_BASE + offset, prog_buf, padded))
    {
        ui_message("Update failed", "Flash write error", NULL);
        return DFU_STATUS_ERR_PROG;
    }
    dl.written += length;

    percent = dl.written * 100U / dl.total;
    if (percent >= dl.shown + 10U || dl.written == dl.total)
    {
        dl.shown = percent - percent % 10U;
        ui_progress(dl.hdr.fw_version, dl.shown);
    }
    return DFU_STATUS_OK;
}

bool dfu_confirming(void)
{
    return confirm.pending;
}

static bool pressed(press_t *p, bool level, uint32_t now)
{
    if (!level)
    {
        p->released = true;
        p->down = now;
        return false;
    }
    return p->released && (now - p->down) >= PRESS_MS;
}

static void cancel(const char *reason)
{
    confirm.pending = false;
    memset(&dl, 0, sizeof(dl));
    ui_message("Update cancelled", reason, NULL);
    tud_dfu_finish_flashing(DFU_STATUS_ERR_VENDOR);
}

void dfu_task(void)
{
    uint32_t now = HAL_GetTick();

    if (!confirm.pending)
    {
        return;
    }
    if (pressed(&confirm.next, button_next(), now))
    {
        cancel("Declined on the key");
    }
    else if (pressed(&confirm.ok, button(), now))
    {
        confirm.pending = false;
        dl.hdr_ok = true;
        ui_progress(dl.hdr.fw_version, 0);
        tud_dfu_finish_flashing(download(0, prog_buf, confirm.len));
        return;
    }
    else if ((now - confirm.start) >= CONFIRM_MS)
    {
        cancel("Not confirmed in time");
    }
}

static uint8_t manifest(void)
{
    if (!dl.hdr_ok || dl.total == 0 || dl.written != dl.total)
    {
        return DFU_STATUS_ERR_NOTDONE;
    }
    if (!image_slot_ok())
    {
        ui_message("Update failed", "Verification failed", "Send the image again");
        return DFU_STATUS_ERR_VERIFY;
    }
    /* the new version becomes the floor only once it's installed and verified, taken from the
       header in flash that image_slot_ok() just checked, not from what the host sent */
    rollback_raise(((const boot_hdr_t *)BOOT_SLOT_BASE)->fw_version);
    dl.done = true;
    ui_message("Update installed", "Restarting...", NULL);
    return DFU_STATUS_OK;
}

bool dfu_done(void)
{
    return dl.done;
}

//--------------------------------------------------------------------+
// DFU callbacks
//--------------------------------------------------------------------+

uint32_t tud_dfu_get_timeout_cb(uint8_t alt, uint8_t state)
{
    return state == DFU_MANIFEST ? DFU_MANIFEST_MS : DFU_POLL_MS;
}

/*
 * tinyusb's CLRSTATUS, SET_INTERFACE and bus reset go back to dfuIDLE without telling us, so
 * the host can send a new request while block 0 waits for OK. Such a request cancels the
 * confirmation: the press must never apply to anything but the header shown.
 */
static bool cancel_pending(void)
{
    if (!confirm.pending)
    {
        return false;
    }
    confirm.pending = false;
    memset(&dl, 0, sizeof(dl));
    ui_message("Update cancelled", "Interrupted by the host", NULL);
    return true;
}

void tud_dfu_download_cb(uint8_t alt, uint16_t block_num, uint8_t const *data, uint16_t length)
{
    uint8_t status;

    if (cancel_pending())
    {
        tud_dfu_finish_flashing(DFU_STATUS_ERR_VENDOR);
        return;
    }
    if (block_num != 0)
    {
        tud_dfu_finish_flashing(download(block_num, data, length));
        return;
    }
    status = check_header(data, length);
    if (status != DFU_STATUS_OK)
    {
        tud_dfu_finish_flashing(status);
        return;
    }
    /* finished by dfu_task() */
    memcpy(prog_buf, data, length);
    confirm.len = length;
    confirm.start = HAL_GetTick();
    confirm.ok.released = false;
    confirm.next.released = false;
    confirm.pending = true;
    ui_confirm(dl.hdr.fw_version, dfu_installed_version());
}

void tud_dfu_manifest_cb(uint8_t alt)
{
    if (cancel_pending())
    {
        tud_dfu_finish_flashing(DFU_STATUS_ERR_VENDOR);
        return;
    }
    tud_dfu_finish_flashing(manifest());
}

void tud_dfu_abort_cb(uint8_t alt)
{
    memset(&dl, 0, sizeof(dl));
    confirm.pending = false;
}

//--------------------------------------------------------------------+
// Descriptors
//--------------------------------------------------------------------+

static tusb_desc_device_t const desc_device = {
  .bLength         = sizeof(tusb_desc_device_t),
  .bDescriptorType = TUSB_DESC_DEVICE,
  .bcdUSB          = 0x0200,
  .bDeviceClass    = 0x00,
  .bDeviceSubClass = 0x00,
  .bDeviceProtocol = 0x00,
  .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,

  .idVendor  = 0xCafe,
  .idProduct = 0x8009,
  .bcdDevice = 0x0100,

  .iManufacturer = 0x01,
  .iProduct      = 0x02,
  .iSerialNumber = 0x03,

  .bNumConfigurations = 0x01,
};

uint8_t const *tud_descriptor_device_cb(void)
{
  return (uint8_t const *) &desc_device;
}

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_DFU_DESC_LEN(1))

uint8_t const desc_configuration[] =
{
  // Config number, interface count, string index, total length, attribute, power in mA
  TUD_CONFIG_DESCRIPTOR(1, 1, 0, CONFIG_TOTAL_LEN, 0x00, 100),

  // Interface number, alternate count, string index, attributes, detach timeout, transfer size
  /* manifestation tolerant: reports the verification result, then main() resets into the app */
  TUD_DFU_DESCRIPTOR(0, 1, 4, DFU_ATTR_CAN_DOWNLOAD | DFU_ATTR_MANIFESTATION_TOLERANT, 1000, CFG_TUD_DFU_XFER_BUFSIZE),
};

uint8_t const *tud_descriptor_configuration_cb(uint8_t index)
{
  (void) index;
  return desc_configuration;
}

enum {
  STRID_LANGID = 0,
  STRID_MANUFACTURER,
  STRID_PRODUCT,
  STRID_SERIAL,
  STRID_SLOT,
};

static char const *string_desc_arr[] = {
  (const char[]){0x09, 0x04}, // 0: is supported language is English (0x0409)
  "TinyUSB",                  // 1: Manufacturer
  "k4chn1k key bootloader",   // 2: Product
  NULL,                       // 3: Serial number, from MCU unique ID
  "signed app image",         // 4: DFU alternate setting
};

static char serial_str[2 * 12 + 1];

static const char *serial_number(void)
{
  static const char hex[] = "0123456789ABCDEF";
  /* read-only area must be read by words, byte access is a bus fault */
  const volatile uint32_t *uid = (const volatile uint32_t *) UID_BASE;

  if (serial_str[0] == '\0')
  {
    for (int i = 0; i < 3; i++)
    {
      uint32_t w = uid[i];
      for (int j = 0; j < 8; j++)
      {
        serial_str[8 * i + j] = hex[(w >> (28 - 4 * j)) & 0x0f];
      }
    }
  }
  return serial_str;
}

static uint16_t _desc_str[32 + 1];

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
  (void) langid;
  size_t chr_count;

  if (index == STRID_LANGID)
  {
    memcpy(&_desc_str[1], string_desc_arr[0], 2);
    chr_count = 1;
  }
  else
  {
    if (!(index < sizeof(string_desc_arr) / sizeof(string_desc_arr[0])))
    {
      return NULL;
    }

    const char *str = (index == STRID_SERIAL) ? serial_number() : string_desc_arr[index];
    size_t const max_count = sizeof(_desc_str) / sizeof(_desc_str[0]) - 1;

    chr_count = strlen(str);
    if (chr_count > max_count)
    {
      chr_count = max_count;
    }
    for (size_t i = 0; i < chr_count; i++)
    {
      _desc_str[1 + i] = str[i];
    }
  }

  // first byte is length (including header), second byte is string type
  _desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));
  return _desc_str;
}
