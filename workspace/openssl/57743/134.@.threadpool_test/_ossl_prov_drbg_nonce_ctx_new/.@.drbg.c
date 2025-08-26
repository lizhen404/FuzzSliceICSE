#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../providers/implementations/rands/drbg.c"
// 1 "../providers/implementations/rands/drbg.c" 2
// 10 "../providers/implementations/rands/drbg.c"
// 11 "../providers/implementations/rands/drbg.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/crypto.h"
// 12 "../providers/implementations/rands/drbg.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/err.h"
// 13 "../providers/implementations/rands/drbg.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/rand.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/evp.h"
// 14 "../providers/implementations/rands/drbg.c" 2

#include "/StaticSlicer/test_lib/openssl/include/crypto/rand.h"
#include "/StaticSlicer/test_lib/openssl/include/crypto/rand_pool.h"
// 16 "../providers/implementations/rands/drbg.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/proverr.h"
// 17 "../providers/implementations/rands/drbg.c" 2
#include "/StaticSlicer/test_lib/openssl/providers/implementations/rands/drbg_local.h"
#include "/StaticSlicer/test_lib/openssl/providers/common/include/prov/provider_ctx.h"
// 18 "../providers/implementations/rands/drbg.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/thread_once.h"
// 19 "../providers/implementations/rands/drbg.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/cryptlib.h"
// 20 "../providers/implementations/rands/drbg.c" 2
#include "/StaticSlicer/test_lib/openssl/providers/implementations/include/prov/seeding.h"
// 21 "../providers/implementations/rands/drbg.c" 2


#include "/StaticSlicer/test_lib/openssl/providers/common/include/prov/providercommon.h"
// 24 "../providers/implementations/rands/drbg.c" 2
#include "/StaticSlicer/test_lib/openssl/providers/common/include/prov/fipscommon.h"
// 25 "../providers/implementations/rands/drbg.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 26 "../providers/implementations/rands/drbg.c" 2
// 41 "../providers/implementations/rands/drbg.c"


// 145 "../providers/implementations/rands/drbg.c"
typedef struct prov_drbg_nonce_global_st {
CRYPTO_RWLOCK *rand_nonce_lock;
int rand_nonce_count;
} PROV_DRBG_NONCE_GLOBAL;
// 276 "../providers/implementations/rands/drbg.c"
void *ossl_prov_drbg_nonce_ctx_new(OSSL_LIB_CTX *libctx)
{
PROV_DRBG_NONCE_GLOBAL *dngbl = CRYPTO_zalloc(sizeof(*dngbl), "../providers/implementations/rands/drbg.c", 278);

if (dngbl == ((void*)0))
return ((void*)0);

dngbl->rand_nonce_lock = CRYPTO_THREAD_lock_new();
if (dngbl->rand_nonce_lock == ((void*)0)) {
CRYPTO_free(dngbl, "../providers/implementations/rands/drbg.c", 285);
return ((void*)0);
}

return dngbl;
}

void ossl_prov_drbg_nonce_ctx_free(void *vdngbl)
{
PROV_DRBG_NONCE_GLOBAL *dngbl = vdngbl;

if (dngbl == ((void*)0))
return;

CRYPTO_THREAD_lock_free(dngbl->rand_nonce_lock);

CRYPTO_free(dngbl, "../providers/implementations/rands/drbg.c", 301);
}


// 354 "../providers/implementations/rands/drbg.c"
// 481 "../providers/implementations/rands/drbg.c"
// 601 "../providers/implementations/rands/drbg.c"
// 629 "../providers/implementations/rands/drbg.c"
// 734 "../providers/implementations/rands/drbg.c"
// 788 "../providers/implementations/rands/drbg.c"