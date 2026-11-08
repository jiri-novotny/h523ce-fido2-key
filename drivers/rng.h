#ifndef __RNG_H__
#define __RNG_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void rng_init(void);
bool rng_read(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* __RNG_H__ */
