#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/quic_vlint.c"
// 1 "../crypto/quic_vlint.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/quic_vlint.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/e_os.h"
// 2 "../crypto/quic_vlint.c" 2




uint64_t ossl_quic_vlint_decode_unchecked(const unsigned char *buf)
{
uint8_t first_byte = buf[0];
size_t sz = ossl_quic_vlint_decode_len(first_byte);

if (sz == 1)
return first_byte & 0x3F;

if (sz == 2)
return ((uint64_t)(first_byte & 0x3F) << 8)
| buf[1];

if (sz == 4)
return ((uint64_t)(first_byte & 0x3F) << 24)
| ((uint64_t)buf[1] << 16)
| ((uint64_t)buf[2] << 8)
| buf[3];

return ((uint64_t)(first_byte & 0x3F) << 56)
| ((uint64_t)buf[1] << 48)
| ((uint64_t)buf[2] << 40)
| ((uint64_t)buf[3] << 32)
| ((uint64_t)buf[4] << 24)
| ((uint64_t)buf[5] << 16)
| ((uint64_t)buf[6] << 8)
| buf[7];
}
