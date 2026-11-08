#include <string.h>

#include "cbor.h"

#define CBOR_MAX_DEPTH 8

void cbor_reader_init(cbor_reader_t *r, const uint8_t *data, size_t len)
{
    r->p = data;
    r->end = data + len;
    r->err = false;
}

static bool fail(cbor_reader_t *r)
{
    r->err = true;
    return false;
}

bool cbor_read(cbor_reader_t *r, cbor_item_t *item)
{
    uint8_t ib, info;
    uint64_t val = 0;
    size_t n;

    if (r->err || r->p >= r->end)
    {
        return fail(r);
    }

    item->start = r->p;
    ib = *r->p++;
    item->type = ib >> 5;
    info = ib & 0x1f;

    if (info < 24)
    {
        val = info;
    }
    else if (info <= 27)
    {
        n = 1U << (info - 24);
        if ((size_t)(r->end - r->p) < n)
        {
            return fail(r);
        }
        for (size_t i = 0; i < n; i++)
        {
            val = (val << 8) | *r->p++;
        }
    }
    else
    {
        /* indefinite lengths and reserved values are not allowed in CTAP2 */
        return fail(r);
    }

    if (item->type == CBOR_SIMPLE && info > 24)
    {
        /* floats */
        return fail(r);
    }

    item->val = val;
    item->ptr = NULL;

    if (item->type == CBOR_BYTES || item->type == CBOR_TEXT)
    {
        if (val > (uint64_t)(r->end - r->p))
        {
            return fail(r);
        }
        item->ptr = r->p;
        r->p += val;
    }

    return true;
}

static bool skip_depth(cbor_reader_t *r, int depth);

static bool skip_children(cbor_reader_t *r, const cbor_item_t *item, int depth)
{
    uint64_t count;

    if (item->type == CBOR_ARRAY)
    {
        count = item->val;
    }
    else if (item->type == CBOR_MAP)
    {
        count = item->val * 2;
    }
    else if (item->type == CBOR_TAG)
    {
        count = 1;
    }
    else
    {
        return true;
    }

    if (depth >= CBOR_MAX_DEPTH)
    {
        return fail(r);
    }
    for (uint64_t i = 0; i < count; i++)
    {
        if (!skip_depth(r, depth + 1))
        {
            return false;
        }
    }
    return true;
}

static bool skip_depth(cbor_reader_t *r, int depth)
{
    cbor_item_t item;

    if (!cbor_read(r, &item))
    {
        return false;
    }
    return skip_children(r, &item, depth);
}

bool cbor_skip(cbor_reader_t *r)
{
    return skip_depth(r, 0);
}

bool cbor_skip_rest(cbor_reader_t *r, const cbor_item_t *item)
{
    return skip_children(r, item, 0);
}

bool cbor_is_int(const cbor_item_t *item)
{
    return (item->type == CBOR_UINT && item->val <= INT64_MAX) || (item->type == CBOR_NINT && item->val <= INT64_MAX);
}

int64_t cbor_int(const cbor_item_t *item)
{
    return item->type == CBOR_UINT ? (int64_t)item->val : -1 - (int64_t)item->val;
}

bool cbor_is_bool(const cbor_item_t *item)
{
    return item->type == CBOR_SIMPLE && (item->val == CBOR_TRUE || item->val == CBOR_FALSE);
}

bool cbor_text_eq(const cbor_item_t *item, const char *str)
{
    size_t len = strlen(str);
    return item->type == CBOR_TEXT && item->val == len && memcmp(item->ptr, str, len) == 0;
}

void cbor_writer_init(cbor_writer_t *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->err = false;
}

void cbor_put_raw(cbor_writer_t *w, const void *data, size_t len)
{
    if (w->err || w->cap - w->len < len)
    {
        w->err = true;
        return;
    }
    memcpy(&w->buf[w->len], data, len);
    w->len += len;
}

static void put_head(cbor_writer_t *w, uint8_t type, uint64_t val)
{
    uint8_t hdr[9];
    size_t n;

    type <<= 5;
    if (val < 24)
    {
        hdr[0] = type | (uint8_t)val;
        n = 0;
    }
    else if (val <= 0xff)
    {
        hdr[0] = type | 24;
        n = 1;
    }
    else if (val <= 0xffff)
    {
        hdr[0] = type | 25;
        n = 2;
    }
    else if (val <= 0xffffffff)
    {
        hdr[0] = type | 26;
        n = 4;
    }
    else
    {
        hdr[0] = type | 27;
        n = 8;
    }
    for (size_t i = 0; i < n; i++)
    {
        hdr[n - i] = (uint8_t)(val >> (8 * i));
    }
    cbor_put_raw(w, hdr, n + 1);
}

void cbor_put_uint(cbor_writer_t *w, uint64_t val)
{
    put_head(w, CBOR_UINT, val);
}

void cbor_put_int(cbor_writer_t *w, int64_t val)
{
    if (val >= 0)
    {
        put_head(w, CBOR_UINT, (uint64_t)val);
    }
    else
    {
        put_head(w, CBOR_NINT, (uint64_t)(-1 - val));
    }
}

void cbor_put_bytes(cbor_writer_t *w, const void *data, size_t len)
{
    put_head(w, CBOR_BYTES, len);
    cbor_put_raw(w, data, len);
}

void cbor_put_textn(cbor_writer_t *w, const char *str, size_t len)
{
    put_head(w, CBOR_TEXT, len);
    cbor_put_raw(w, str, len);
}

void cbor_put_text(cbor_writer_t *w, const char *str)
{
    cbor_put_textn(w, str, strlen(str));
}

void cbor_put_array(cbor_writer_t *w, size_t count)
{
    put_head(w, CBOR_ARRAY, count);
}

void cbor_put_map(cbor_writer_t *w, size_t count)
{
    put_head(w, CBOR_MAP, count);
}

void cbor_put_bool(cbor_writer_t *w, bool val)
{
    put_head(w, CBOR_SIMPLE, val ? CBOR_TRUE : CBOR_FALSE);
}
