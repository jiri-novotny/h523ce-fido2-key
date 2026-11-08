#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include CMSIS_device_header
#include "monocypher.h"

#include "boot.h"
#include "iflash.h"
#include "rng.h"

#include "kv.h"

#define KV_SECTORS     (KV_SIZE / FLASH_SECTOR_SIZE)
#define KV_SLOT_SIZE   512U
#define KV_PER_SECTOR  (FLASH_SECTOR_SIZE / KV_SLOT_SIZE)
#define KV_SLOTS       (KV_SECTORS * KV_PER_SECTOR)
#define KV_RESERVE     KV_PER_SECTOR /* blank slots only compaction may take */
#define KV_TOMB_OFFSET (KV_SLOT_SIZE - IFLASH_QW_SIZE)
#define KV_MAGIC       0x3156564BU /* "KVV1" */

/*
 * Slot of 512 bytes: header quad-word, encrypted record, unused, tombstone quad-word (last).
 * A record is written data first and header last, so a slot with a header was written in full;
 * anything else that isn't blank is dead. The header's sequence number orders two copies of a
 * key left by a power loss between writing the new one and marking the old one, the newer wins.
 *
 * When fewer than KV_RESERVE + 1 slots are blank, a sector without live records is erased, or
 * the live records of the sector with the most dead slots are copied to blank slots elsewhere
 * and the sector is erased. Every sector takes its turn, so the wear spreads over the area.
 */
typedef struct
{
    uint32_t magic;
    uint8_t key[KV_KEY_SIZE];
    uint32_t seq;
} header_t;

typedef struct
{
    uint8_t nonce[24];
    uint8_t mac[16];
    uint8_t ct[KV_DATA_MAX];
} blob_t;

_Static_assert(sizeof(header_t) == IFLASH_QW_SIZE, "kv header is a quad-word");
_Static_assert(sizeof(blob_t) % IFLASH_QW_SIZE == 0 && IFLASH_QW_SIZE + sizeof(blob_t) <= KV_TOMB_OFFSET,
               "kv record fits the slot");
_Static_assert(KV_MAX + 1U < KV_SLOTS - KV_RESERVE, "kv needs dead slots to compact");

enum
{
    SLOT_BLANK,
    SLOT_LIVE,
    SLOT_DEAD,
};

typedef struct
{
    uint8_t key[KV_KEY_SIZE];
    uint32_t seq;
    uint8_t state;
} slot_t;

static slot_t slots[KV_SLOTS];
static uint32_t seq;    /* highest sequence number in use */
static uint32_t cursor; /* where the search for a blank slot starts, spreads the writes */
static uint8_t kv_key[32];
static blob_t blob;
static uint8_t plain[KV_DATA_MAX];

static uint32_t slot_addr(uint32_t i)
{
    return BOOT_DATA_BASE + i * KV_SLOT_SIZE;
}

static uint32_t count(uint32_t first, uint32_t n, uint8_t state)
{
    uint32_t c = 0;

    for (uint32_t i = first; i < first + n; i++)
    {
        c += slots[i].state == state;
    }
    return c;
}

static void make_ad(const slot_t *s, uint8_t ad[KV_KEY_SIZE + 4])
{
    memcpy(ad, s->key, KV_KEY_SIZE);
    memcpy(ad + KV_KEY_SIZE, &s->seq, 4);
}

/* into plain, the caller wipes it */
static bool decrypt(uint32_t i)
{
    uint8_t ad[KV_KEY_SIZE + 4];

    for (uint32_t q = 0; q < sizeof(blob) / IFLASH_QW_SIZE; q++)
    {
        if (!iflash_read_qw(slot_addr(i) + (q + 1U) * IFLASH_QW_SIZE, (uint8_t *)&blob + q * IFLASH_QW_SIZE))
        {
            return false;
        }
    }
    make_ad(&slots[i], ad);
    return crypto_aead_unlock(plain, blob.mac, kv_key, blob.nonce, ad, sizeof(ad), blob.ct, KV_DATA_MAX) == 0;
}

static void scan_slot(uint32_t i)
{
    uint8_t qw[IFLASH_QW_SIZE];
    header_t h;

    slots[i].state = SLOT_DEAD;
    if (!iflash_read_qw(slot_addr(i), &h))
    {
        return;
    }
    if (iflash_blank_qw(&h))
    {
        /* blank only if nothing of an interrupted write is there */
        for (uint32_t off = IFLASH_QW_SIZE; off < KV_SLOT_SIZE; off += IFLASH_QW_SIZE)
        {
            if (!iflash_read_qw(slot_addr(i) + off, qw) || !iflash_blank_qw(qw))
            {
                return;
            }
        }
        slots[i].state = SLOT_BLANK;
        return;
    }
    if (h.magic != KV_MAGIC || !iflash_read_qw(slot_addr(i) + KV_TOMB_OFFSET, qw) || !iflash_blank_qw(qw))
    {
        return;
    }
    memcpy(slots[i].key, h.key, KV_KEY_SIZE);
    slots[i].seq = h.seq;
    if (h.seq > seq)
    {
        seq = h.seq;
    }
    if (decrypt(i))
    {
        slots[i].state = SLOT_LIVE;
    }
}

static int find(const uint8_t key[KV_KEY_SIZE])
{
    for (uint32_t i = 0; i < KV_SLOTS; i++)
    {
        if (slots[i].state == SLOT_LIVE && memcmp(slots[i].key, key, KV_KEY_SIZE) == 0)
        {
            return (int)i;
        }
    }
    return -1;
}

static bool kill(uint32_t i)
{
    static const uint8_t zero[IFLASH_QW_SIZE] = {0};

    slots[i].state = SLOT_DEAD;
    return iflash_program_qw(slot_addr(i) + KV_TOMB_OFFSET, zero);
}

/* blank slot outside sector skip, reserve: may take the last KV_RESERVE blank slots */
static int alloc(uint32_t skip, bool reserve)
{
    if (!reserve && count(0, KV_SLOTS, SLOT_BLANK) <= KV_RESERVE)
    {
        return -1;
    }
    for (uint32_t n = 0; n < KV_SLOTS; n++)
    {
        uint32_t i = (cursor + n) % KV_SLOTS;

        if (slots[i].state == SLOT_BLANK && i / KV_PER_SECTOR != skip)
        {
            cursor = (i + 1U) % KV_SLOTS;
            return (int)i;
        }
    }
    return -1;
}

/* writes len bytes of data (may be plain) as the newest copy of key into blank slot i */
static bool put(uint32_t i, const uint8_t key[KV_KEY_SIZE], const void *data, size_t len)
{
    slot_t *s = &slots[i];
    header_t h = {.magic = KV_MAGIC, .seq = ++seq};
    uint8_t ad[KV_KEY_SIZE + 4];
    bool ok;

    memcpy(h.key, key, KV_KEY_SIZE);
    memcpy(s->key, key, KV_KEY_SIZE);
    s->seq = h.seq;
    s->state = SLOT_DEAD; /* until the header is in */

    if (data != plain)
    {
        memcpy(plain, data, len);
    }
    memset(plain + len, 0, KV_DATA_MAX - len);
    make_ad(s, ad);
    ok = rng_read(blob.nonce, sizeof(blob.nonce));
    if (ok)
    {
        crypto_aead_lock(blob.ct, blob.mac, kv_key, blob.nonce, ad, sizeof(ad), plain, KV_DATA_MAX);
    }
    crypto_wipe(plain, sizeof(plain));

    for (uint32_t q = 0; ok && q < sizeof(blob) / IFLASH_QW_SIZE; q++)
    {
        ok = iflash_program_qw(slot_addr(i) + (q + 1U) * IFLASH_QW_SIZE, (uint8_t *)&blob + q * IFLASH_QW_SIZE);
    }
    ok = ok && iflash_program_qw(slot_addr(i), &h);
    if (ok)
    {
        s->state = SLOT_LIVE;
    }
    return ok;
}

static bool erase_sector(uint32_t sec)
{
    if (!iflash_erase_sector(slot_addr(sec * KV_PER_SECTOR)))
    {
        return false;
    }
    for (uint32_t i = sec * KV_PER_SECTOR; i < (sec + 1U) * KV_PER_SECTOR; i++)
    {
        slots[i].state = SLOT_BLANK;
    }
    return true;
}

static bool compact(void)
{
    uint32_t blank = count(0, KV_SLOTS, SLOT_BLANK);
    uint32_t best = KV_SECTORS, best_dead = 0;

    /* sectors without live records first, they cost nothing to free */
    for (uint32_t sec = 0; sec < KV_SECTORS; sec++)
    {
        uint32_t first = sec * KV_PER_SECTOR;

        if (count(first, KV_PER_SECTOR, SLOT_LIVE) == 0 && count(first, KV_PER_SECTOR, SLOT_BLANK) < KV_PER_SECTOR &&
            !erase_sector(sec))
        {
            return false;
        }
    }
    blank = count(0, KV_SLOTS, SLOT_BLANK);
    if (blank > KV_RESERVE)
    {
        return true;
    }

    for (uint32_t sec = 0; sec < KV_SECTORS; sec++)
    {
        uint32_t first = sec * KV_PER_SECTOR;
        uint32_t dead = count(first, KV_PER_SECTOR, SLOT_DEAD);

        if (dead > best_dead &&
            count(first, KV_PER_SECTOR, SLOT_LIVE) <= blank - count(first, KV_PER_SECTOR, SLOT_BLANK))
        {
            best = sec;
            best_dead = dead;
        }
    }
    if (best == KV_SECTORS)
    {
        return false;
    }

    /* the copies are newer, a power loss before the erase leaves duplicates which kv_init() sorts out */
    for (uint32_t i = best * KV_PER_SECTOR; i < (best + 1U) * KV_PER_SECTOR; i++)
    {
        int j;

        if (slots[i].state != SLOT_LIVE)
        {
            continue;
        }
        if (!decrypt(i) || (j = alloc(best, true)) < 0 || !put((uint32_t)j, slots[i].key, plain, KV_DATA_MAX))
        {
            crypto_wipe(plain, sizeof(plain));
            return false;
        }
    }
    return erase_sector(best);
}

void kv_init(const uint8_t key[32])
{
    memcpy(kv_key, key, sizeof(kv_key));
    seq = 0;
    for (uint32_t i = 0; i < KV_SLOTS; i++)
    {
        scan_slot(i);
    }
    crypto_wipe(plain, sizeof(plain));

    /* two copies of a key: a write or a compaction was cut short, the newer one wins */
    for (uint32_t i = 0; i < KV_SLOTS; i++)
    {
        for (uint32_t j = i + 1U; slots[i].state == SLOT_LIVE && j < KV_SLOTS; j++)
        {
            if (slots[j].state == SLOT_LIVE && memcmp(slots[i].key, slots[j].key, KV_KEY_SIZE) == 0)
            {
                kill(slots[i].seq < slots[j].seq ? i : j);
            }
        }
    }

    if (count(0, KV_SLOTS, SLOT_BLANK) <= KV_RESERVE)
    {
        compact();
    }
}

bool kv_read(const uint8_t key[KV_KEY_SIZE], void *buf, size_t len)
{
    int i = find(key);
    bool ok = i >= 0 && decrypt((uint32_t)i);

    if (ok)
    {
        memcpy(buf, plain, len < KV_DATA_MAX ? len : KV_DATA_MAX);
    }
    crypto_wipe(plain, sizeof(plain));
    return ok;
}

bool kv_exists(const uint8_t key[KV_KEY_SIZE])
{
    return find(key) >= 0;
}

bool kv_write(const uint8_t key[KV_KEY_SIZE], const void *data, size_t len)
{
    int i, old;

    if (len > KV_DATA_MAX || (find(key) < 0 && count(0, KV_SLOTS, SLOT_LIVE) >= KV_MAX))
    {
        return false;
    }
    while ((i = alloc(KV_SECTORS, false)) < 0)
    {
        if (!compact())
        {
            return false;
        }
    }
    /* after compact(), which may have moved the old copy */
    old = find(key);
    if (!put((uint32_t)i, key, data, len))
    {
        return false;
    }
    if (old >= 0)
    {
        kill((uint32_t)old);
    }
    return true;
}

bool kv_delete(const uint8_t key[KV_KEY_SIZE])
{
    int i = find(key);

    return i >= 0 && kill((uint32_t)i);
}

bool kv_erase_all(void)
{
    bool ok = true;

    for (uint32_t sec = 0; sec < KV_SECTORS; sec++)
    {
        ok = erase_sector(sec) && ok;
    }
    return ok;
}

void kv_foreach(kv_cb_t cb, void *ctx)
{
    for (uint32_t i = 0; i < KV_SLOTS; i++)
    {
        if (slots[i].state == SLOT_LIVE && !cb(slots[i].key, ctx))
        {
            break;
        }
    }
}
