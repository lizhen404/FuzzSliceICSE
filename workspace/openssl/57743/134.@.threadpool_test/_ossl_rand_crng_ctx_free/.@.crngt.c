#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../providers/implementations/rands/crngt.c"
// 1 "../providers/implementations/rands/crngt.c" 2
// 15 "../providers/implementations/rands/crngt.c"
// 16 "../providers/implementations/rands/crngt.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/evp.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/core_dispatch.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/params.h"
// 17 "../providers/implementations/rands/crngt.c" 2


#include "/StaticSlicer/test_lib/openssl/include/openssl/self_test.h"
// 20 "../providers/implementations/rands/crngt.c" 2
#include "/StaticSlicer/test_lib/openssl/providers/common/include/prov/providercommon.h"
// 21 "../providers/implementations/rands/crngt.c" 2
#include "/StaticSlicer/test_lib/openssl/providers/common/include/prov/provider_ctx.h"
// 22 "../providers/implementations/rands/crngt.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"
// 23 "../providers/implementations/rands/crngt.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/rand_pool.h"
// 24 "../providers/implementations/rands/crngt.c" 2
#include "/StaticSlicer/test_lib/openssl/providers/implementations/rands/drbg_local.h"
// 25 "../providers/implementations/rands/crngt.c" 2
#include "/StaticSlicer/test_lib/openssl/providers/implementations/include/prov/seeding.h"
// 26 "../providers/implementations/rands/crngt.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 27 "../providers/implementations/rands/crngt.c" 2

typedef struct crng_test_global_st {
unsigned char crngt_prev[64];
EVP_MD *md;
int preloaded;
CRYPTO_RWLOCK *lock;
} CRNG_TEST_GLOBAL;

void ossl_rand_crng_ctx_free(void *vcrngt_glob)
{
CRNG_TEST_GLOBAL *crngt_glob = vcrngt_glob;

CRYPTO_THREAD_lock_free(crngt_glob->lock);
EVP_MD_free(crngt_glob->md);
CRYPTO_free(crngt_glob, "../providers/implementations/rands/crngt.c", 62);
}

void *ossl_rand_crng_ctx_new(OSSL_LIB_CTX *ctx)
{
CRNG_TEST_GLOBAL *crngt_glob = CRYPTO_zalloc(sizeof(*crngt_glob), "../providers/implementations/rands/crngt.c", 67);

if (crngt_glob == ((void*)0))
return ((void*)0);

if ((crngt_glob->md = EVP_MD_fetch(ctx, "SHA256", "")) == ((void*)0)) {
CRYPTO_free(crngt_glob, "../providers/implementations/rands/crngt.c", 73);
return ((void*)0);
}

if ((crngt_glob->lock = CRYPTO_THREAD_lock_new()) == ((void*)0)) {
EVP_MD_free(crngt_glob->md);
CRYPTO_free(crngt_glob, "../providers/implementations/rands/crngt.c", 79);
return ((void*)0);
}

return crngt_glob;
}
