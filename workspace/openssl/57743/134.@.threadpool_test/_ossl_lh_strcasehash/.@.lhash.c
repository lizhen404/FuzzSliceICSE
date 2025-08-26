#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/lhash/lhash.c"
// 1 "../crypto/lhash/lhash.c" 2
// 10 "../crypto/lhash/lhash.c"
// 11 "../crypto/lhash/lhash.c" 2
// 12 "../crypto/lhash/lhash.c" 2
#include <stdlib.h>
// 13 "../crypto/lhash/lhash.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/crypto.h"
// 14 "../crypto/lhash/lhash.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/lhash.h"
// 15 "../crypto/lhash/lhash.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/err.h"
// 16 "../crypto/lhash/lhash.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/ctype.h"
// 17 "../crypto/lhash/lhash.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/lhash.h"
// 18 "../crypto/lhash/lhash.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/lhash/lhash_local.h"
// 19 "../crypto/lhash/lhash.c" 2
// 43 "../crypto/lhash/lhash.c"
// 399 "../crypto/lhash/lhash.c"
unsigned long ossl_lh_strcasehash(const char *c)
{
unsigned long ret = 0;
long n;
unsigned long v;
int r;



const long int case_adjust = ~0x20;


if (c == ((void*)0) || *c == '\0')
return ret;

for (n = 0x100; *c != '\0'; n += 0x100) {
v = n | (case_adjust & *c);
r = (int)((v >> 2) ^ v) & 0x0f;

ret = (ret << r) | (unsigned long)((uint64_t)ret >> (32 - r));
ret &= 0xFFFFFFFFL;
ret ^= v * v;
c++;
}
return (ret >> 16) ^ ret;
}
