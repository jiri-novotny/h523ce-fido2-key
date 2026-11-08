#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include CMSIS_device_header

#include "btl_pubkey.h"
#include "obk.h"

#include "image.h"

#define CRYPTO_TIMEOUT_MS 1000

_Static_assert(sizeof(boot_hdr_t) == 128 && offsetof(boot_hdr_t, sig_r) == BOOT_HDR_SIGNED, "boot_hdr_t layout");

/*
 * Anti-rollback counter: append-only records in the HDPL1 OBK area, which only the bootloader
 * can access. The first 256 B are left for the ST debug authentication data (RM0481 §66.2.7).
 */
#define RB_MAGIC   0x31564252U /* "RBV1" */
#define RB_BASE    (FLASH_OBK_HDPL1_BASE_NS + 0x100U)
#define RB_RECORDS ((FLASH_OBK_HDPL1_SIZE - 0x100U) / OBK_QW_SIZE)

typedef struct
{
    uint32_t magic;
    uint32_t version;
    uint32_t inv_version;
    uint32_t reserved;
} rb_record_t;

/* NIST P-256, big endian; a = -3 is passed as |a| with the negative sign flag */
static const uint8_t p256_p[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t p256_a[32] = {[31] = 0x03};
static const uint8_t p256_gx[32] = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6,
                                    0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb,
                                    0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
static const uint8_t p256_gy[32] = {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
                                    0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
                                    0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
static const uint8_t p256_n[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
                                   0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};

static const volatile rb_record_t *rb_record(uint32_t i)
{
    return (const volatile rb_record_t *)(RB_BASE + i * OBK_QW_SIZE);
}

static bool rb_valid(const volatile rb_record_t *r)
{
    return r->magic == RB_MAGIC && r->inv_version == ~r->version;
}

uint32_t rollback_min(void)
{
    uint32_t min = 0;

    for (uint32_t i = 0; i < RB_RECORDS; i++)
    {
        const volatile rb_record_t *r = rb_record(i);

        if (rb_valid(r) && r->version > min)
        {
            min = r->version;
        }
    }
    return min;
}

bool rollback_raise(uint32_t version)
{
    rb_record_t rec = {.magic = RB_MAGIC, .version = version, .inv_version = ~version, .reserved = 0xFFFFFFFFU};

    if (version <= rollback_min())
    {
        return true;
    }
    /* a record half written by a power loss is skipped, the next blank one is used */
    for (uint32_t i = 0; i < RB_RECORDS; i++)
    {
        uint32_t addr = (uint32_t)rb_record(i);

        if (obk_blank(addr, OBK_QW_SIZE) && obk_program(addr, &rec, sizeof(rec)) && rb_valid(rb_record(i)))
        {
            return true;
        }
    }
    /* full, would need the alternate sector swap - versions >= the last stored one still boot */
    return false;
}

static bool sha256(const void *data, uint32_t len, uint8_t out[32])
{
    HASH_HandleTypeDef hhash = {.Instance = HASH};
    bool ok;

    __HAL_RCC_HASH_CLK_ENABLE();
    hhash.Init.DataType = HASH_BYTE_SWAP;
    hhash.Init.Algorithm = HASH_ALGOSELECTION_SHA256;
    ok = HAL_HASH_Init(&hhash) == HAL_OK &&
         HAL_HASH_Start(&hhash, data, len, out, CRYPTO_TIMEOUT_MS) == HAL_OK;
    HAL_HASH_DeInit(&hhash);
    __HAL_RCC_HASH_CLK_DISABLE();
    return ok;
}

/* PKA in limited mode (H523): ECDSA verification only, needs the RNG running (rng_init()) */
static bool ecdsa_p256_verify(const uint8_t digest[32], const uint8_t r[32], const uint8_t s[32])
{
    PKA_HandleTypeDef hpka = {.Instance = PKA};
    PKA_ECDSAVerifInTypeDef in = {
        .primeOrderSize = sizeof(p256_n),
        .modulusSize = sizeof(p256_p),
        .coefSign = 1,
        .coef = p256_a,
        .modulus = p256_p,
        .basePointX = p256_gx,
        .basePointY = p256_gy,
        .pPubKeyCurvePtX = &btl_pubkey[0],
        .pPubKeyCurvePtY = &btl_pubkey[32],
        .RSign = r,
        .SSign = s,
        .hash = digest,
        .primeOrder = p256_n,
    };
    bool ok;

    __HAL_RCC_PKA_CLK_ENABLE();
    ok = HAL_PKA_Init(&hpka) == HAL_OK && HAL_PKA_ECDSAVerif(&hpka, &in, CRYPTO_TIMEOUT_MS) == HAL_OK &&
         HAL_PKA_ECDSAVerif_IsValidSignature(&hpka) == 1U;
    HAL_PKA_DeInit(&hpka);
    __HAL_RCC_PKA_CLK_DISABLE();
    return ok;
}

bool image_header_ok(const boot_hdr_t *hdr)
{
    uint8_t digest[32];

    if (hdr->magic != BOOT_HDR_MAGIC || hdr->hdr_version != BOOT_HDR_VERSION || hdr->image_size == 0 ||
        hdr->image_size > BOOT_APP_MAX || (hdr->image_size % 16U) != 0 || hdr->fw_version < rollback_min())
    {
        return false;
    }
    return sha256(hdr, BOOT_HDR_SIGNED, digest) && ecdsa_p256_verify(digest, hdr->sig_r, hdr->sig_s);
}

bool image_slot_ok(void)
{
    const boot_hdr_t *hdr = (const boot_hdr_t *)BOOT_SLOT_BASE;
    uint8_t digest[32];

    /* the header is signed and covers the image hash, check it first */
    return image_header_ok(hdr) && sha256((const void *)BOOT_APP_BASE, hdr->image_size, digest) &&
           memcmp(digest, hdr->image_sha256, sizeof(digest)) == 0;
}
