#ifndef __DISPLAY_H__
#define __DISPLAY_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

/* SSD1306 128x32 OLED on I2C1 (PB6 SCL, PB7 SDA) */
#define DISPLAY_WIDTH       128
#define DISPLAY_HEIGHT      32
#define DISPLAY_LINES       4  /* small text, 5x7 font */
#define DISPLAY_COLS        25
#define DISPLAY_LARGE_LINES 2  /* large text, font scaled by 2 */
#define DISPLAY_LARGE_COLS  12
#ifndef DISPLAY_ROTATE_180
#define DISPLAY_ROTATE_180  1  /* 0 for the module's default orientation */
#endif

/* finds the display (address 0x3C or 0x3D), false if none answers; the other calls then do nothing */
bool display_init(void);

/* drawing goes to a frame buffer, display_flush() sends it */
void display_clear(void);
void display_text(uint8_t line, const char *s);
void display_text_large(uint8_t line, const char *s);
bool display_flush(void);

#ifdef __cplusplus
}
#endif
#endif /* __DISPLAY_H__ */
