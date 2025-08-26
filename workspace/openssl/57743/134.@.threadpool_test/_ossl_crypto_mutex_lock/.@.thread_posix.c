#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/thread/arch/thread_posix.c"
// 1 "../crypto/thread/arch/thread_posix.c" 2
// 10 "../crypto/thread/arch/thread_posix.c"
#include "/StaticSlicer/test_lib/openssl/include/internal/thread_arch.h"
# include <sys/types.h>
# include <unistd.h>
// 11 "../crypto/thread/arch/thread_posix.c" 2



# include <errno.h>
// 15 "../crypto/thread/arch/thread_posix.c" 2



static void *thread_start_thunk(void *vthread)
{
CRYPTO_THREAD *thread;
CRYPTO_THREAD_RETVAL ret;

thread = (CRYPTO_THREAD *)vthread;

ret = thread->routine(thread->data);
ossl_crypto_mutex_lock(thread->statelock);
do { (thread)->state |= ((1UL << 0)); } while ((void)0, 0);
thread->retval = ret;
ossl_crypto_condvar_broadcast(thread->condvar);
ossl_crypto_mutex_unlock(thread->statelock);

return ((void*)0);
}

int ossl_crypto_thread_native_spawn(CRYPTO_THREAD *thread)
{
int ret;
pthread_attr_t attr;
pthread_t *handle;

handle = CRYPTO_zalloc(sizeof(*handle), "../crypto/thread/arch/thread_posix.c", 41);
if (handle == ((void*)0))
goto fail;

pthread_attr_init(&attr);
if (!thread->joinable)
pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
ret = pthread_create(handle, &attr, thread_start_thunk, thread);
pthread_attr_destroy(&attr);

if (ret != 0)
goto fail;

thread->handle = handle;
return 1;

fail:
thread->handle = ((void*)0);
CRYPTO_free(handle, "../crypto/thread/arch/thread_posix.c", 59);
return 0;
}

CRYPTO_MUTEX *ossl_crypto_mutex_new(void)
{
pthread_mutex_t *mutex;

if ((mutex = CRYPTO_zalloc(sizeof(*mutex), "../crypto/thread/arch/thread_posix.c", 100)) == ((void*)0))
return ((void*)0);
if (pthread_mutex_init(mutex, ((void*)0)) != 0) {
CRYPTO_free(mutex, "../crypto/thread/arch/thread_posix.c", 103);
return ((void*)0);
}
return (CRYPTO_MUTEX *)mutex;
}

void ossl_crypto_mutex_lock(CRYPTO_MUTEX *mutex)
{
int rc;
pthread_mutex_t *mutex_p;

mutex_p = (pthread_mutex_t *)mutex;
rc = pthread_mutex_lock(mutex_p);
(void)((rc == 0) ? 0 : (OPENSSL_die("assertion failed: rc == 0", "../crypto/thread/arch/thread_posix.c", 128), 1));
}

void ossl_crypto_mutex_unlock(CRYPTO_MUTEX *mutex)
{
int rc;
pthread_mutex_t *mutex_p;

mutex_p = (pthread_mutex_t *)mutex;
rc = pthread_mutex_unlock(mutex_p);
(void)((rc == 0) ? 0 : (OPENSSL_die("assertion failed: rc == 0", "../crypto/thread/arch/thread_posix.c", 138), 1));
}

void ossl_crypto_mutex_free(CRYPTO_MUTEX **mutex)
{
pthread_mutex_t **mutex_p;

if (mutex == ((void*)0))
return;

mutex_p = (pthread_mutex_t **)mutex;
if (*mutex_p != ((void*)0))
pthread_mutex_destroy(*mutex_p);
CRYPTO_free(*mutex_p, "../crypto/thread/arch/thread_posix.c", 151);
*mutex = ((void*)0);
}

CRYPTO_CONDVAR *ossl_crypto_condvar_new(void)
{
pthread_cond_t *cv_p;

if ((cv_p = CRYPTO_zalloc(sizeof(*cv_p), "../crypto/thread/arch/thread_posix.c", 159)) == ((void*)0))
return ((void*)0);
if (pthread_cond_init(cv_p, ((void*)0)) != 0) {
CRYPTO_free(cv_p, "../crypto/thread/arch/thread_posix.c", 162);
return ((void*)0);
}
return (CRYPTO_CONDVAR *) cv_p;
}

void ossl_crypto_condvar_wait(CRYPTO_CONDVAR *cv, CRYPTO_MUTEX *mutex)
{
pthread_cond_t *cv_p;
pthread_mutex_t *mutex_p;

cv_p = (pthread_cond_t *)cv;
mutex_p = (pthread_mutex_t *)mutex;
pthread_cond_wait(cv_p, mutex_p);
}

void ossl_crypto_condvar_broadcast(CRYPTO_CONDVAR *cv)
{
pthread_cond_t *cv_p;

cv_p = (pthread_cond_t *)cv;
pthread_cond_broadcast(cv_p);
}

void ossl_crypto_condvar_free(CRYPTO_CONDVAR **cv)
{
pthread_cond_t **cv_p;

if (cv == ((void*)0))
return;

cv_p = (pthread_cond_t **)cv;
if (*cv_p != ((void*)0))
pthread_cond_destroy(*cv_p);
CRYPTO_free(*cv_p, "../crypto/thread/arch/thread_posix.c", 229);
*cv_p = ((void*)0);
}