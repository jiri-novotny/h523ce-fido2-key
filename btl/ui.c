#include <stdint.h>
#include <string.h>

#include "display.h"

#include "ui.h"

/* "<label>v<version>", or "<label>none" for version 0 */
static const char *ver(char *buf, const char *label, uint32_t version)
{
    char digits[10];
    size_t n = strlen(label), d = 0;

    memcpy(buf, label, n);
    if (version == 0)
    {
        memcpy(buf + n, "none", 5);
        return buf;
    }
    do
    {
        digits[d++] = (char)('0' + version % 10U);
        version /= 10U;
    } while (version);
    buf[n++] = 'v';
    while (d)
    {
        buf[n++] = digits[--d];
    }
    buf[n] = '\0';
    return buf;
}

void ui_init(void)
{
    display_init();
}

void ui_message(const char *line0, const char *line1, const char *line2)
{
    display_clear();
    display_text(0, line0);
    display_text(1, line1 ? line1 : "");
    display_text(2, line2 ? line2 : "");
    display_flush();
}

void ui_waiting(uint32_t installed, uint32_t min_version)
{
    char a[DISPLAY_COLS + 1], b[DISPLAY_COLS + 1];

    display_clear();
    display_text(0, "Bootloader");
    display_text(1, ver(a, "Installed: ", installed));
    display_text(2, ver(b, "Oldest allowed: ", min_version));
    display_text(3, "Waiting for update");
    display_flush();
}

void ui_confirm(uint32_t version, uint32_t installed)
{
    char a[DISPLAY_COLS + 1], b[DISPLAY_COLS + 1];

    display_clear();
    ver(a, "Install ", version);
    memcpy(a + strlen(a), "?", 2);
    display_text(0, a);
    display_text(1, ver(b, "Installed: ", installed));
    display_text(3, "OK: install  Next: cancel");
    display_flush();
}

void ui_progress(uint32_t version, uint32_t percent)
{
    char a[DISPLAY_COLS + 1], p[5];
    size_t n = 0;

    if (percent >= 100U)
    {
        p[n++] = '1';
    }
    if (percent >= 10U)
    {
        p[n++] = (char)('0' + (percent / 10U) % 10U);
    }
    p[n++] = (char)('0' + percent % 10U);
    p[n++] = '%';
    p[n] = '\0';

    display_clear();
    display_text(0, ver(a, "Installing ", version));
    display_text_large(1, p);
    display_flush();
}
