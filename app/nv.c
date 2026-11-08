#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include CMSIS_device_header

#include "boot.h"
#include "iflash.h"
#include "kv.h"

#include "nv.h"

/* the data area after the record store */
#define NV_BASE      (BOOT_DATA_BASE + KV_SIZE)
#define NV_SECTORS   ((BOOT_DATA_SIZE - KV_SIZE) / FLASH_SECTOR_SIZE)
#define NV_RECORDS   (FLASH_SECTOR_SIZE / IFLASH_QW_SIZE - 1U) /* the first quad-word is the sector header */
#define NV_HDR_MAGIC 0x3156564EU /* "NVV1" */
#define NV_REC_MAGIC 0x4345524EU /* "NREC" */

/*
 * Ring of sectors, each starts with a header holding a sequence number, then records are
 * appended, the last valid one wins. A full sector moves on to the next one in the ring, which
 * is erased and gets header seq + 1 and the record, so every sector wears the same. The previous
 * sector still holds the last record when the power is lost in the middle of a move.
 *
 * A quad-word that doesn't read (ECC double error, iflash.h) is skipped.
 */
typedef struct
{
    uint32_t magic;
    uint32_t seq;
    uint32_t inv_seq;
    uint32_t inv_magic;
} header_t;

typedef struct
{
    nv_t nv;
    uint32_t check;
} record_t;

_Static_assert(sizeof(header_t) == IFLASH_QW_SIZE && sizeof(record_t) == IFLASH_QW_SIZE, "nv quad-word layout");
_Static_assert(NV_SECTORS >= 2, "nv needs at least two sectors");

static uint32_t cur = NV_SECTORS; /* current sector, NV_SECTORS before the first save */
static uint32_t cur_seq;
static uint32_t next; /* next record to program in the current sector */

static uint32_t sector_addr(uint32_t s)
{
    return NV_BASE + s * FLASH_SECTOR_SIZE;
}

static uint32_t record_addr(uint32_t s, uint32_t i)
{
    return sector_addr(s) + (i + 1U) * IFLASH_QW_SIZE;
}

static uint32_t crc32(const void *data, uint32_t len)
{
    const uint8_t *p = data;
    uint32_t crc = 0xFFFFFFFFU;

    while (len--)
    {
        crc ^= *p++;
        for (int k = 0; k < 8; k++)
        {
            crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U)));
        }
    }
    return ~crc;
}

static uint32_t record_check(const nv_t *nv)
{
    return crc32(nv, sizeof(*nv)) ^ NV_REC_MAGIC;
}

static bool header_seq(uint32_t s, uint32_t *seq)
{
    header_t h;

    if (!iflash_read_qw(sector_addr(s), &h) || h.magic != NV_HDR_MAGIC || h.inv_magic != ~NV_HDR_MAGIC ||
        h.inv_seq != ~h.seq)
    {
        return false;
    }
    *seq = h.seq;
    return true;
}

/* last valid record of sector s, *free_at: first blank record */
static bool sector_last(uint32_t s, nv_t *nv, uint32_t *free_at)
{
    record_t r;
    bool found = false;
    uint32_t i;

    for (i = 0; i < NV_RECORDS; i++)
    {
        if (!iflash_read_qw(record_addr(s, i), &r))
        {
            continue; /* interrupted write, skipped */
        }
        if (iflash_blank_qw(&r))
        {
            break;
        }
        if (r.check == record_check(&r.nv))
        {
            *nv = r.nv;
            found = true;
        }
    }
    *free_at = i;
    return found;
}

bool nv_load(nv_t *nv)
{
    uint32_t prev = NV_SECTORS, prev_seq = 0, seq, free_at;

    cur = NV_SECTORS;
    for (uint32_t s = 0; s < NV_SECTORS; s++)
    {
        if (!header_seq(s, &seq))
        {
            continue;
        }
        if (cur == NV_SECTORS || seq > cur_seq)
        {
            prev = cur;
            prev_seq = cur_seq;
            cur = s;
            cur_seq = seq;
        }
        else if (prev == NV_SECTORS || seq > prev_seq)
        {
            prev = s;
            prev_seq = seq;
        }
    }
    if (cur == NV_SECTORS)
    {
        return false;
    }
    if (sector_last(cur, nv, &next))
    {
        return true;
    }
    /* power loss right after a move, the previous sector still has the record */
    return prev < NV_SECTORS && sector_last(prev, nv, &free_at);
}

bool nv_save(const nv_t *nv)
{
    record_t r = {.nv = *nv, .check = record_check(nv)};
    uint32_t s;
    header_t h;

    /* a quad-word that fails (interrupted before, or bad cell) is left behind */
    while (cur < NV_SECTORS && next < NV_RECORDS)
    {
        if (iflash_program_qw(record_addr(cur, next++), &r))
        {
            return true;
        }
    }

    s = (cur < NV_SECTORS) ? (cur + 1U) % NV_SECTORS : 0U;
    h.magic = NV_HDR_MAGIC;
    h.seq = cur_seq + 1U;
    h.inv_seq = ~h.seq;
    h.inv_magic = ~NV_HDR_MAGIC;
    if (!iflash_erase_sector(sector_addr(s)) || !iflash_program_qw(sector_addr(s), &h) ||
        !iflash_program_qw(record_addr(s, 0), &r))
    {
        return false;
    }
    cur = s;
    cur_seq = h.seq;
    next = 1;
    return true;
}
