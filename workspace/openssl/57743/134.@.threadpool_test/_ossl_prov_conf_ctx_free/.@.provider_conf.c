#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/provider_conf.c"
// 1 "../crypto/provider_conf.c" 2
// 10 "../crypto/provider_conf.c"
// 11 "../crypto/provider_conf.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/trace.h"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/safestack.h"
// 12 "../crypto/provider_conf.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/err.h"
// 13 "../crypto/provider_conf.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/conf.h"
// 14 "../crypto/provider_conf.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/provider.h"
// 16 "../crypto/provider_conf.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/provider.h"
// 17 "../crypto/provider_conf.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"
// 18 "../crypto/provider_conf.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/provider_local.h"
// 19 "../crypto/provider_conf.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 20 "../crypto/provider_conf.c" 2

struct stack_st_OSSL_PROVIDER; typedef int (*sk_OSSL_PROVIDER_compfunc)(const OSSL_PROVIDER * const *a, const OSSL_PROVIDER *const *b); typedef void (*sk_OSSL_PROVIDER_freefunc)(OSSL_PROVIDER *a); typedef OSSL_PROVIDER * (*sk_OSSL_PROVIDER_copyfunc)(const OSSL_PROVIDER *a);
static  inline void sk_OSSL_PROVIDER_pop_free(struct stack_st_OSSL_PROVIDER *sk, sk_OSSL_PROVIDER_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); }
typedef struct {
CRYPTO_RWLOCK *lock;
struct stack_st_OSSL_PROVIDER *activated_providers;
} PROVIDER_CONF_GLOBAL;

void *ossl_prov_conf_ctx_new(OSSL_LIB_CTX *libctx)
{
PROVIDER_CONF_GLOBAL *pcgbl = CRYPTO_zalloc(sizeof(*pcgbl), "../crypto/provider_conf.c", 32);

if (pcgbl == ((void*)0))
return ((void*)0);

pcgbl->lock = CRYPTO_THREAD_lock_new();
if (pcgbl->lock == ((void*)0)) {
CRYPTO_free(pcgbl, "../crypto/provider_conf.c", 39);
return ((void*)0);
}

return pcgbl;
}

void ossl_prov_conf_ctx_free(void *vpcgbl)
{
PROVIDER_CONF_GLOBAL *pcgbl = vpcgbl;

sk_OSSL_PROVIDER_pop_free(pcgbl->activated_providers,
ossl_provider_free);

((void)0);
CRYPTO_THREAD_lock_free(pcgbl->lock);
CRYPTO_free(pcgbl, "../crypto/provider_conf.c", 55);
}

// 74 "../crypto/provider_conf.c"
// 155 "../crypto/provider_conf.c"
// 201 "../crypto/provider_conf.c"