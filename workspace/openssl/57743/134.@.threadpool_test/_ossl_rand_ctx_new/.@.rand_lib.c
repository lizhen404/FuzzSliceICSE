#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/rand/rand_lib.c"
// 1 "../crypto/rand/rand_lib.c" 2
// 13 "../crypto/rand/rand_lib.c"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/err.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/opensslconf.h"
# include <limits.h>
# include <time.h>
// 14 "../crypto/rand/rand_lib.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/core_names.h"
// 16 "../crypto/rand/rand_lib.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/e_os.h"
// 17 "../crypto/rand/rand_lib.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/thread_once.h"
// 18 "../crypto/rand/rand_lib.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/rand.h"
#include "/StaticSlicer/test_lib/openssl/include/crypto/rand_pool.h"
// 19 "../crypto/rand/rand_lib.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/cryptlib.h"
// 20 "../crypto/rand/rand_lib.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/rand/rand_local.h"
// 21 "../crypto/rand/rand_lib.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 22 "../crypto/rand/rand_lib.c" 2




// 27 "../crypto/rand/rand_lib.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/conf.h"
// 28 "../crypto/rand/rand_lib.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/trace.h"
// 29 "../crypto/rand/rand_lib.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/engine.h"
// 30 "../crypto/rand/rand_lib.c" 2

#include "/StaticSlicer/test_lib/openssl/providers/implementations/include/prov/seeding.h"
// 32 "../crypto/rand/rand_lib.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/property.h"
// 34 "../crypto/rand/rand_lib.c" 2















// 123 "../crypto/rand/rand_lib.c"
// 334 "../crypto/rand/rand_lib.c"
typedef struct rand_global_st {
// 401 "../crypto/rand/rand_lib.c"
CRYPTO_RWLOCK *lock;

EVP_RAND_CTX *seed;
// 416 "../crypto/rand/rand_lib.c"
EVP_RAND_CTX *primary;
// 426 "../crypto/rand/rand_lib.c"
CRYPTO_THREAD_LOCAL public;
// 436 "../crypto/rand/rand_lib.c"
CRYPTO_THREAD_LOCAL private;


char *rng_name;
char *rng_cipher;
char *rng_digest;
char *rng_propq;


char *seed_name;
char *seed_propq;
} RAND_GLOBAL;





void *ossl_rand_ctx_new(OSSL_LIB_CTX *libctx)
{
RAND_GLOBAL *dgbl = CRYPTO_zalloc(sizeof(*dgbl), "../crypto/rand/rand_lib.c", 455);

if (dgbl == ((void*)0))
return ((void*)0);






OPENSSL_init_crypto(0x00040000L, ((void*)0));


dgbl->lock = CRYPTO_THREAD_lock_new();
if (dgbl->lock == ((void*)0))
goto err1;

if (!CRYPTO_THREAD_init_local(&dgbl->private, ((void*)0)))
goto err1;

if (!CRYPTO_THREAD_init_local(&dgbl->public, ((void*)0)))
goto err2;

return dgbl;

err2:
CRYPTO_THREAD_cleanup_local(&dgbl->private);
err1:
CRYPTO_THREAD_lock_free(dgbl->lock);
CRYPTO_free(dgbl, "../crypto/rand/rand_lib.c", 484);
return ((void*)0);
}

void ossl_rand_ctx_free(void *vdgbl)
{
RAND_GLOBAL *dgbl = vdgbl;

if (dgbl == ((void*)0))
return;

CRYPTO_THREAD_lock_free(dgbl->lock);
CRYPTO_THREAD_cleanup_local(&dgbl->private);
CRYPTO_THREAD_cleanup_local(&dgbl->public);
EVP_RAND_CTX_free(dgbl->primary);
EVP_RAND_CTX_free(dgbl->seed);
CRYPTO_free(dgbl->rng_name, "../crypto/rand/rand_lib.c", 500);
CRYPTO_free(dgbl->rng_cipher, "../crypto/rand/rand_lib.c", 501);
CRYPTO_free(dgbl->rng_digest, "../crypto/rand/rand_lib.c", 502);
CRYPTO_free(dgbl->rng_propq, "../crypto/rand/rand_lib.c", 503);
CRYPTO_free(dgbl->seed_name, "../crypto/rand/rand_lib.c", 504);
CRYPTO_free(dgbl->seed_propq, "../crypto/rand/rand_lib.c", 505);

CRYPTO_free(dgbl, "../crypto/rand/rand_lib.c", 507);
}

// 829 "../crypto/rand/rand_lib.c"