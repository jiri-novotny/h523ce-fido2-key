#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include CMSIS_device_header
#include "stm32h5xx_ll_bus.h"
#include "stm32h5xx_ll_gpio.h"
#include "stm32h5xx_ll_i2c.h"
#include "stm32h5xx_ll_rcc.h"

#include "font5x7.h"

#include "display.h"

#define I2C_TIMEOUT_MS 20
#define CTRL_CMD       0x00 /* SSD1306 control byte: commands follow */
#define CTRL_DATA      0x40 /* display RAM data follows */

static uint8_t addr; /* 7-bit, 0 if no display */
static uint8_t fb[DISPLAY_WIDTH * DISPLAY_HEIGHT / 8]; /* pages of 8 rows, bit 0 = top */

/*----------------------------------------------------------------------------*/
/* I2C1 master, polling                                                       */
/*----------------------------------------------------------------------------*/
static bool wait_flag(uint32_t flag)
{
  uint32_t start = HAL_GetTick();

  while ((I2C1->ISR & flag) == 0)
  {
    if (I2C1->ISR & I2C_ISR_NACKF)
    {
      return false;
    }
    if ((HAL_GetTick() - start) > I2C_TIMEOUT_MS)
    {
      return false;
    }
  }
  return true;
}

static void set_chunk(uint32_t left, uint32_t cr2)
{
  uint32_t n = left > 255U ? 255U : left;

  cr2 |= (n << I2C_CR2_NBYTES_Pos) | (left > 255U ? I2C_CR2_RELOAD : I2C_CR2_AUTOEND);
  I2C1->CR2 = cr2;
}

/* control byte, then len bytes, as one write transfer */
static bool i2c_write(uint8_t dev, uint8_t ctrl, const uint8_t *data, uint32_t len)
{
  uint32_t left = len + 1U, chunk = 0;
  bool ok = true;

  set_chunk(left, ((uint32_t)dev << 1) | I2C_CR2_START);
  for (uint32_t i = 0; ok && i <= len; i++)
  {
    if (chunk == 255U)
    {
      /* RELOAD: the next chunk once the previous one is out */
      ok = wait_flag(I2C_ISR_TCR);
      left -= chunk;
      chunk = 0;
      set_chunk(left, (uint32_t)dev << 1);
    }
    ok = ok && wait_flag(I2C_ISR_TXIS);
    if (ok)
    {
      I2C1->TXDR = (i == 0) ? ctrl : data[i - 1U];
      chunk++;
    }
  }

  /* AUTOEND sends the stop, also after a NACK */
  if (!wait_flag(I2C_ISR_STOPF))
  {
    ok = false;
    I2C1->CR2 |= I2C_CR2_STOP;
  }
  if (I2C1->ISR & I2C_ISR_NACKF)
  {
    ok = false;
  }
  if (!ok)
  {
    I2C1->ISR |= I2C_ISR_TXE; /* flush a byte the NACK left in TXDR */
  }
  I2C1->ICR = I2C_ICR_NACKCF | I2C_ICR_STOPCF;
  return ok;
}

static void i2c_init(void)
{
  LL_GPIO_InitTypeDef gpio = {0};
  uint32_t f, presc, t;

  LL_AHB2_GRP1_EnableClock(LL_AHB2_GRP1_PERIPH_GPIOB);
  gpio.Pin = LL_GPIO_PIN_6 | LL_GPIO_PIN_7;
  gpio.Mode = LL_GPIO_MODE_ALTERNATE;
  gpio.Speed = LL_GPIO_SPEED_FREQ_LOW;
  gpio.OutputType = LL_GPIO_OUTPUT_OPENDRAIN;
  gpio.Pull = LL_GPIO_PULL_NO; /* pull-ups on the display module */
  gpio.Alternate = LL_GPIO_AF_4;
  LL_GPIO_Init(GPIOB, &gpio);

  LL_RCC_SetI2CClockSource(LL_RCC_I2C1_CLKSOURCE_PCLK1);
  LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_I2C1);

  /* 400 kHz: tick of at most 40 ns, SCL low 1.4 us, high 0.8 us, data setup 400 ns, hold 120 ns */
  f = LL_RCC_GetI2CClockFreq(LL_RCC_I2C1_CLKSOURCE);
  presc = (f + 24999999U) / 25000000U - 1U;
  if (presc > 15U)
  {
    presc = 15U;
  }
  t = (presc + 1U) * 1000000000U / f; /* tick in ns, at most 40 */
  I2C1->CR1 = 0;
  I2C1->TIMINGR = (presc << I2C_TIMINGR_PRESC_Pos) | (((400U + t - 1U) / t - 1U) << I2C_TIMINGR_SCLDEL_Pos) |
                  (((120U + t - 1U) / t - 1U) << I2C_TIMINGR_SDADEL_Pos) |
                  (((800U + t - 1U) / t - 1U) << I2C_TIMINGR_SCLH_Pos) | (((1400U + t - 1U) / t - 1U) << I2C_TIMINGR_SCLL_Pos);
  I2C1->CR1 = I2C_CR1_PE;
}

/*----------------------------------------------------------------------------*/
/* SSD1306                                                                    */
/*----------------------------------------------------------------------------*/
static const uint8_t init_seq[] = {
    0xAE,       /* display off */
    0xD5, 0x80, /* clock divide, oscillator */
    0xA8, 0x1F, /* multiplex: 32 rows */
    0xD3, 0x00, /* display offset */
    0x40,       /* start line 0 */
    0x8D, 0x14, /* charge pump on (no external VCC) */
    0x20, 0x00, /* horizontal addressing */
#if DISPLAY_ROTATE_180
    0xA0,       /* column 0 is SEG0 */
    0xC0,       /* scan COM from the top */
#else
    0xA1,       /* column 127 is SEG0 */
    0xC8,       /* scan COM from the bottom */
#endif
    0xDA, 0x02, /* COM pins: sequential, 128x32 */
    0x81, 0x8F, /* contrast */
    0xD9, 0xF1, /* pre-charge */
    0xDB, 0x40, /* VCOMH deselect level */
    0xA4,       /* show RAM */
    0xA6,       /* normal, not inverted */
    0x2E,       /* scrolling off */
};

bool display_init(void)
{
  static const uint8_t on = 0xAF;
  static const uint8_t candidates[] = {0x3C, 0x3D};

  i2c_init();
  addr = 0;
  for (uint32_t i = 0; i < sizeof(candidates); i++)
  {
    if (i2c_write(candidates[i], CTRL_CMD, init_seq, sizeof(init_seq)))
    {
      addr = candidates[i];
      break;
    }
  }
  if (addr == 0)
  {
    return false;
  }
  display_clear();
  return display_flush() && i2c_write(addr, CTRL_CMD, &on, 1);
}

void display_clear(void)
{
  memset(fb, 0, sizeof(fb));
}

static const uint8_t *glyph(char c)
{
  if (c < FONT5X7_FIRST || c > FONT5X7_LAST)
  {
    c = '?';
  }
  return font5x7[c - FONT5X7_FIRST];
}

void display_text(uint8_t line, const char *s)
{
  uint8_t *p;

  if (line >= DISPLAY_LINES)
  {
    return;
  }
  p = &fb[line * DISPLAY_WIDTH];
  memset(p, 0, DISPLAY_WIDTH);
  for (uint32_t col = 0; *s && col < DISPLAY_COLS; col++, s++)
  {
    memcpy(&p[col * FONT5X7_WIDTH], glyph(*s), FONT5X7_WIDTH);
  }
}

/* every column doubled, every bit doubled into two pages */
void display_text_large(uint8_t line, const char *s)
{
  uint8_t *top, *bottom;

  if (line >= DISPLAY_LARGE_LINES)
  {
    return;
  }
  top = &fb[line * 2 * DISPLAY_WIDTH];
  bottom = top + DISPLAY_WIDTH;
  memset(top, 0, 2 * DISPLAY_WIDTH);
  for (uint32_t col = 0; *s && col < DISPLAY_LARGE_COLS; col++, s++)
  {
    const uint8_t *g = glyph(*s);

    for (uint32_t x = 0; x < FONT5X7_WIDTH; x++)
    {
      uint16_t wide = 0;

      for (uint32_t y = 0; y < 8; y++)
      {
        if (g[x] & (1U << y))
        {
          wide |= 3U << (2 * y);
        }
      }
      for (uint32_t k = 0; k < 2; k++)
      {
        top[(col * FONT5X7_WIDTH + x) * 2 + k] = (uint8_t)wide;
        bottom[(col * FONT5X7_WIDTH + x) * 2 + k] = (uint8_t)(wide >> 8);
      }
    }
  }
}

bool display_flush(void)
{
  static const uint8_t window[] = {
      0x21, 0, DISPLAY_WIDTH - 1,            /* columns */
      0x22, 0, DISPLAY_HEIGHT / 8 - 1,       /* pages */
  };

  return addr != 0 && i2c_write(addr, CTRL_CMD, window, sizeof(window)) &&
         i2c_write(addr, CTRL_DATA, fb, sizeof(fb));
}
