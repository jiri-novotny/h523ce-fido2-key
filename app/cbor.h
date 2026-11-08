#ifndef __CBOR_H__
#define __CBOR_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* minimal CBOR (RFC 8949) subset needed by CTAP2: definite lengths only, no floats, no tags */

#define CBOR_UINT   0
#define CBOR_NINT   1
#define CBOR_BYTES  2
#define CBOR_TEXT   3
#define CBOR_ARRAY  4
#define CBOR_MAP    5
#define CBOR_TAG    6
#define CBOR_SIMPLE 7

#define CBOR_FALSE 20
#define CBOR_TRUE  21
#define CBOR_NULL  22

/* decoder ------------------------------------------------------------------ */

typedef struct
{
    const uint8_t *p;
    const uint8_t *end;
    bool err;
} cbor_reader_t;

/* decoded item header; for bytes/text ptr/len point into the input */
typedef struct
{
    uint8_t type;
    uint64_t val; /* uint value, -1 - val for nint, length for bytes/text, count for array/map */
    const uint8_t *ptr;
    const uint8_t *start; /* first byte of the encoded item */
} cbor_item_t;

void cbor_reader_init(cbor_reader_t *r, const uint8_t *data, size_t len);
bool cbor_read(cbor_reader_t *r, cbor_item_t *item);       /* reads header (and string payload) */
bool cbor_skip(cbor_reader_t *r);                          /* skips one complete item */
bool cbor_skip_rest(cbor_reader_t *r, const cbor_item_t *item); /* skips children of an array/map header */

bool cbor_is_int(const cbor_item_t *item);
int64_t cbor_int(const cbor_item_t *item);
bool cbor_is_bool(const cbor_item_t *item);
bool cbor_text_eq(const cbor_item_t *item, const char *str);

/* encoder ------------------------------------------------------------------ */

typedef struct
{
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool err;
} cbor_writer_t;

void cbor_writer_init(cbor_writer_t *w, uint8_t *buf, size_t cap);
void cbor_put_uint(cbor_writer_t *w, uint64_t val);
void cbor_put_int(cbor_writer_t *w, int64_t val);
void cbor_put_bytes(cbor_writer_t *w, const void *data, size_t len);
void cbor_put_text(cbor_writer_t *w, const char *str);
void cbor_put_textn(cbor_writer_t *w, const char *str, size_t len);
void cbor_put_array(cbor_writer_t *w, size_t count);
void cbor_put_map(cbor_writer_t *w, size_t count);
void cbor_put_bool(cbor_writer_t *w, bool val);
void cbor_put_raw(cbor_writer_t *w, const void *data, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* __CBOR_H__ */
