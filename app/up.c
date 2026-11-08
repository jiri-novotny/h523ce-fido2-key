#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include CMSIS_device_header

#include "display.h"
#include "gpio.h"

#include "up.h"

#define DEBOUNCE_MS   30
#define WAIT_BLINK_MS 100
#define WINK_BLINK_MS 50
#define WINK_TOGGLES  20
#define BOOT_SCREEN_MS 3000

#define HINT_CONFIRM "OK: confirm  Next: cancel"

typedef struct
{
    bool raw;
    bool stable;
    uint32_t tick;
} button_t;

static button_t ok_button, next_button;
static uint32_t press_count = 0; /* OK, tools/fido_test.py simulates presses through it */
static uint32_t next_count = 0;

static bool waiting = false;
static uint32_t wink_toggles = 0;
static uint32_t led_tick = 0;

/* the screen is blank when idle, an OLED left on one picture burns in */
static bool screen_on = false;
static uint32_t screen_tick = 0;
static bool prompt_set = false;
static const char *hint = HINT_CONFIRM;

/* U+00C0..U+017F without accents, for account names */
static const char latin[] = "AAAAAAACEEEEIIIIDNOOOOOxOUUUUYTsaaaaaaaceeeeiiiidnooooo/ouuuuyty"
                            "AaAaAaCcCcCcCcDdDdEeEeEeEeEeGgGgGgGgHhHhIiIiIiIiIiJjJjKkkLlLlLlL"
                            "lLlNnNnNnnNnOoOoOoOoRrRrRrSsSsSsSsTtTtTtUuUuUuUuUuUuWwYyYZzZzZzs";

static void screen(bool on)
{
    if (!on)
    {
        display_clear();
    }
    display_flush();
    screen_on = on;
    screen_tick = HAL_GetTick();
}

void up_init(void)
{
    if (display_init())
    {
        display_text_large(0, "k4chn1k");
        display_text(3, "FIDO2 security key");
        screen(true);
    }
}

/* true once per debounced press */
static bool debounce(button_t *b, bool level, uint32_t now)
{
    if (level != b->raw)
    {
        b->raw = level;
        b->tick = now;
    }
    else if (level != b->stable && (now - b->tick) >= DEBOUNCE_MS)
    {
        b->stable = level;
        return level;
    }
    return false;
}

void up_tick(void)
{
    uint32_t now = HAL_GetTick();

    press_count += debounce(&ok_button, button(), now);
    next_count += debounce(&next_button, button_next(), now);

    if (waiting)
    {
        if ((now - led_tick) >= WAIT_BLINK_MS)
        {
            led_tick = now;
            led_toggle();
        }
    }
    else if (wink_toggles)
    {
        if ((now - led_tick) >= WINK_BLINK_MS)
        {
            led_tick = now;
            led_toggle();
            if (--wink_toggles == 0)
            {
                led_run(false);
                screen(false);
            }
        }
    }
    else if (screen_on && (now - screen_tick) >= BOOT_SCREEN_MS)
    {
        screen(false);
    }
}

uint32_t up_press_count(void)
{
    return press_count;
}

uint32_t up_next_count(void)
{
    return next_count;
}

void up_hint(const char *text)
{
    hint = text;
}

/* ASCII only, keeps the end: the registrable domain is the end of an rpId */
static void site_line(uint8_t line, const char *s, size_t len)
{
    char buf[DISPLAY_COLS + 1];
    size_t n = 0;

    if (len > DISPLAY_COLS)
    {
        buf[n++] = '.';
        buf[n++] = '.';
        s += len - (DISPLAY_COLS - 2);
        len = DISPLAY_COLS - 2;
    }
    for (size_t i = 0; i < len; i++)
    {
        buf[n++] = (s[i] >= 0x20 && s[i] < 0x7F) ? s[i] : '?';
    }
    buf[n] = '\0';
    display_text(line, buf);
}

/* UTF-8, accents dropped from Latin letters, cut with ".." when too long */
static void account_line(uint8_t line, const uint8_t *s, size_t len)
{
    char buf[DISPLAY_COLS + 2];
    size_t n = 0;

    for (size_t i = 0; i < len && n <= DISPLAY_COLS;)
    {
        uint32_t cp = s[i++];
        uint32_t more = cp >= 0xF0 ? 3 : cp >= 0xE0 ? 2 : cp >= 0xC0 ? 1 : 0;
        bool stray = cp >= 0x80 && cp < 0xC0;

        cp &= more ? 0x3FU >> more : 0x7FU;
        for (; more && i < len; more--)
        {
            cp = (cp << 6) | (s[i++] & 0x3FU);
        }
        if (stray)
        {
            buf[n++] = '?';
        }
        else if (cp >= 0x20 && cp < 0x7F)
        {
            buf[n++] = (char)cp;
        }
        else if (cp >= 0xC0 && cp < 0x180)
        {
            buf[n++] = latin[cp - 0xC0];
        }
        else
        {
            buf[n++] = '?';
        }
    }
    if (n > DISPLAY_COLS)
    {
        n = DISPLAY_COLS;
        buf[n - 2] = '.';
        buf[n - 1] = '.';
    }
    buf[n] = '\0';
    display_text(line, buf);
}

void up_prompt(const char *action, const void *site, size_t site_len, const void *account, size_t account_len)
{
    display_clear();
    display_text(0, action);
    if (site)
    {
        site_line(1, site, site_len);
    }
    if (account)
    {
        account_line(2, account, account_len);
    }
    display_text(3, hint);
    prompt_set = true;
    if (waiting)
    {
        display_flush(); /* the next item of a list */
    }
}

void up_prompt_text(const char *action, const char *line1, const char *line2)
{
    display_clear();
    display_text(0, action);
    display_text(1, line1 ? line1 : "");
    display_text(2, line2 ? line2 : "");
    display_text(3, hint);
    prompt_set = true;
    if (waiting)
    {
        display_flush(); /* the next item of a list */
    }
}

void up_set_waiting(bool on)
{
    if (on && !waiting)
    {
        if (!prompt_set)
        {
            up_prompt_text("Confirm?", NULL, NULL);
        }
        screen(true);
    }
    if (waiting && !on)
    {
        led_run(false);
        prompt_set = false;
        hint = HINT_CONFIRM;
        screen(false);
    }
    waiting = on;
}

void up_wink(void)
{
    wink_toggles = WINK_TOGGLES;
    if (!waiting)
    {
        display_clear();
        display_text_large(0, "  Hello!");
        screen(true);
    }
}

bool up_led_active(void)
{
    return waiting || wink_toggles;
}
