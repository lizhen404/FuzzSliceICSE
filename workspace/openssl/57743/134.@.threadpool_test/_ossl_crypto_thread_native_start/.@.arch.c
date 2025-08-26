#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/thread/arch.c"
// 1 "../crypto/thread/arch.c" 2
// 10 "../crypto/thread/arch.c"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/configuration.h"
// 11 "../crypto/thread/arch.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/thread_arch.h"
// 12 "../crypto/thread/arch.c" 2

CRYPTO_THREAD *ossl_crypto_thread_native_start(CRYPTO_THREAD_ROUTINE routine,
void *data, int joinable)
{
CRYPTO_THREAD *handle;

if (routine == ((void*)0))
return ((void*)0);

handle = CRYPTO_zalloc(sizeof(*handle), "../crypto/thread/arch.c", 21);
if (handle == ((void*)0))
return ((void*)0);

if ((handle->lock = ossl_crypto_mutex_new()) == ((void*)0))
goto fail;
if ((handle->statelock = ossl_crypto_mutex_new()) == ((void*)0))
goto fail;
if ((handle->condvar = ossl_crypto_condvar_new()) == ((void*)0))
goto fail;

handle->data = data;
handle->routine = routine;
handle->joinable = joinable;

if (ossl_crypto_thread_native_spawn(handle) == 1)
return handle;

fail:
ossl_crypto_condvar_free(&handle->condvar);
ossl_crypto_mutex_free(&handle->statelock);
ossl_crypto_mutex_free(&handle->lock);
CRYPTO_free(handle, "../crypto/thread/arch.c", 43);
return ((void*)0);
}
