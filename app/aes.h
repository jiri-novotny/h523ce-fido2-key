#ifndef __AES_H__
#define __AES_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE  16U
#define AES256_KEY_SIZE 32U

/* AES-256-CBC without padding, len must be a multiple of AES_BLOCK_SIZE, in-place allowed */
void aes256_cbc_encrypt(const uint8_t key[AES256_KEY_SIZE], const uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in,
                        uint8_t *out, size_t len);
void aes256_cbc_decrypt(const uint8_t key[AES256_KEY_SIZE], const uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in,
                        uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* __AES_H__ */
