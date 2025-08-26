#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/thread/internal.c"
// 1 "../crypto/thread/internal.c" 2
// 10 "../crypto/thread/internal.c"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/configuration.h"
// 11 "../crypto/thread/internal.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/e_os2.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/types.h"
// 12 "../crypto/thread/internal.c" 2
// 13 "../crypto/thread/internal.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/crypto.h"
// 14 "../crypto/thread/internal.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/thread.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/thread_arch.h"
// 15 "../crypto/thread/internal.c" 2




static inline uint64_t _ossl_get_avail_threads(OSSL_LIB_CTX_THREADS *tdata)
{

return tdata->max_threads - tdata->active_threads;
}

uint64_t ossl_get_avail_threads(OSSL_LIB_CTX *ctx)
{
uint64_t retval = 0;
OSSL_LIB_CTX_THREADS *tdata = ossl_lib_ctx_get_data(ctx, 19);;

if (tdata == ((void*)0))
return retval;

ossl_crypto_mutex_lock(tdata->lock);
retval = _ossl_get_avail_threads(tdata);
ossl_crypto_mutex_unlock(tdata->lock);

return retval;
}

void *ossl_crypto_thread_start(OSSL_LIB_CTX *ctx, CRYPTO_THREAD_ROUTINE start,
void *data)
{
CRYPTO_THREAD *thread;
OSSL_LIB_CTX_THREADS *tdata = ossl_lib_ctx_get_data(ctx, 19);;

if (tdata == ((void*)0))
return ((void*)0);

ossl_crypto_mutex_lock(tdata->lock);
if (tdata == ((void*)0) || tdata->max_threads == 0) {
ossl_crypto_mutex_unlock(tdata->lock);
return ((void*)0);
}

while (_ossl_get_avail_threads(tdata) == 0)
ossl_crypto_condvar_wait(tdata->cond_finished, tdata->lock);
tdata->active_threads++;
ossl_crypto_mutex_unlock(tdata->lock);

thread = ossl_crypto_thread_native_start(start, data, 1);
if (thread == ((void*)0)) {
ossl_crypto_mutex_lock(tdata->lock);
tdata->active_threads--;
ossl_crypto_mutex_unlock(tdata->lock);
goto fail;
}
thread->ctx = ctx;

fail:
return (void *) thread;
}

// 127 "../crypto/thread/internal.c"
void *ossl_threads_ctx_new(OSSL_LIB_CTX *ctx)
{
struct openssl_threads_st *t = CRYPTO_zalloc(sizeof(*t), "../crypto/thread/internal.c", 129);

if (t == ((void*)0))
return ((void*)0);

t->lock = ossl_crypto_mutex_new();
t->cond_finished = ossl_crypto_condvar_new();

if (t->lock == ((void*)0) || t->cond_finished == ((void*)0))
goto fail;

return t;

fail:
ossl_threads_ctx_free((void *)t);
return ((void*)0);
}

void ossl_threads_ctx_free(void *vdata)
{
OSSL_LIB_CTX_THREADS *t = (OSSL_LIB_CTX_THREADS *) vdata;

if (t == ((void*)0))
return;

ossl_crypto_mutex_free(&t->lock);
ossl_crypto_condvar_free(&t->cond_finished);
CRYPTO_free(t, "../crypto/thread/internal.c", 156);
}