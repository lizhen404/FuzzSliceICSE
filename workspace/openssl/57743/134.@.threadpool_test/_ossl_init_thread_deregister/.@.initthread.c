#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/initthread.c"
// 1 "../crypto/initthread.c" 2
// 10 "../crypto/initthread.c"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/crypto.h"
// 11 "../crypto/initthread.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/core_dispatch.h"
// 12 "../crypto/initthread.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/cryptlib.h"
// 13 "../crypto/initthread.c" 2
#include "/StaticSlicer/test_lib/openssl/providers/common/include/prov/providercommon.h"
// 14 "../crypto/initthread.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/thread_once.h"
// 15 "../crypto/initthread.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 16 "../crypto/initthread.c" 2
// 35 "../crypto/initthread.c"
typedef struct thread_event_handler_st THREAD_EVENT_HANDLER;
struct thread_event_handler_st {

const void *index;

void *arg;
OSSL_thread_stop_handler_fn handfn;
THREAD_EVENT_HANDLER *next;
};


struct stack_st_THREAD_EVENT_HANDLER_PTR; typedef int (*sk_THREAD_EVENT_HANDLER_PTR_compfunc)(const THREAD_EVENT_HANDLER * * const *a, const THREAD_EVENT_HANDLER * *const *b); typedef void (*sk_THREAD_EVENT_HANDLER_PTR_freefunc)(THREAD_EVENT_HANDLER * *a); typedef THREAD_EVENT_HANDLER * * (*sk_THREAD_EVENT_HANDLER_PTR_copyfunc)(const THREAD_EVENT_HANDLER * *a); static  inline int sk_THREAD_EVENT_HANDLER_PTR_num(const struct stack_st_THREAD_EVENT_HANDLER_PTR *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static  inline THREAD_EVENT_HANDLER * *sk_THREAD_EVENT_HANDLER_PTR_value(const struct stack_st_THREAD_EVENT_HANDLER_PTR *sk, int idx) { return (THREAD_EVENT_HANDLER * *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); }
static  inline struct stack_st_THREAD_EVENT_HANDLER_PTR *sk_THREAD_EVENT_HANDLER_PTR_new_null(void) { return (struct stack_st_THREAD_EVENT_HANDLER_PTR *)OPENSSL_sk_new_null(); }
static  inline void sk_THREAD_EVENT_HANDLER_PTR_free(struct stack_st_THREAD_EVENT_HANDLER_PTR *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); }
typedef struct global_tevent_register_st GLOBAL_TEVENT_REGISTER;
struct global_tevent_register_st {
struct stack_st_THREAD_EVENT_HANDLER_PTR *skhands;
CRYPTO_RWLOCK *lock;
};

static GLOBAL_TEVENT_REGISTER *glob_tevent_reg = ((void*)0);

static CRYPTO_ONCE tevent_register_runonce = 0;

static int create_global_tevent_register(void); static int create_global_tevent_register_ossl_ret_ = 0; static void create_global_tevent_register_ossl_(void) { create_global_tevent_register_ossl_ret_ = create_global_tevent_register(); } static int create_global_tevent_register(void)
{
glob_tevent_reg = CRYPTO_zalloc(sizeof(*glob_tevent_reg), "../crypto/initthread.c", 60);
if (glob_tevent_reg == ((void*)0))
return 0;

glob_tevent_reg->skhands = sk_THREAD_EVENT_HANDLER_PTR_new_null();
glob_tevent_reg->lock = CRYPTO_THREAD_lock_new();
if (glob_tevent_reg->skhands == ((void*)0) || glob_tevent_reg->lock == ((void*)0)) {
sk_THREAD_EVENT_HANDLER_PTR_free(glob_tevent_reg->skhands);
CRYPTO_THREAD_lock_free(glob_tevent_reg->lock);
CRYPTO_free(glob_tevent_reg, "../crypto/initthread.c", 69);
glob_tevent_reg = ((void*)0);
return 0;
}

return 1;
}

static GLOBAL_TEVENT_REGISTER *get_global_tevent_register(void)
{
if (!(CRYPTO_THREAD_run_once(&tevent_register_runonce, create_global_tevent_register_ossl_) ? create_global_tevent_register_ossl_ret_ : 0))
return ((void*)0);
return glob_tevent_reg;
}



static int init_thread_deregister(void *arg, int all);

// 139 "../crypto/initthread.c"
static union {
long sane;
CRYPTO_THREAD_LOCAL value;
} destructor_key = { -1 };
// 154 "../crypto/initthread.c"
// 322 "../crypto/initthread.c"
static int init_thread_deregister(void *index, int all)
{
GLOBAL_TEVENT_REGISTER *gtr;
int i;

gtr = get_global_tevent_register();
if (gtr == ((void*)0))
return 0;
if (!all) {
if (!CRYPTO_THREAD_write_lock(gtr->lock))
return 0;
} else {
glob_tevent_reg = ((void*)0);
}
for (i = 0; i < sk_THREAD_EVENT_HANDLER_PTR_num(gtr->skhands); i++) {
THREAD_EVENT_HANDLER **hands
= sk_THREAD_EVENT_HANDLER_PTR_value(gtr->skhands, i);
THREAD_EVENT_HANDLER *curr = ((void*)0), *prev = ((void*)0), *tmp;

if (hands == ((void*)0)) {
if (!all)
CRYPTO_THREAD_unlock(gtr->lock);
return 0;
}
curr = *hands;
while (curr != ((void*)0)) {
if (all || curr->index == index) {
if (prev != ((void*)0))
prev->next = curr->next;
else
*hands = curr->next;
tmp = curr;
curr = curr->next;
CRYPTO_free(tmp, "../crypto/initthread.c", 455);
continue;
}
prev = curr;
curr = curr->next;
}
if (all)
CRYPTO_free(hands, "../crypto/initthread.c", 462);
}
if (all) {
CRYPTO_THREAD_lock_free(gtr->lock);
sk_THREAD_EVENT_HANDLER_PTR_free(gtr->skhands);
CRYPTO_free(gtr, "../crypto/initthread.c", 467);
} else {
CRYPTO_THREAD_unlock(gtr->lock);
}
return 1;
}

int ossl_init_thread_deregister(void *index)
{
return init_thread_deregister(index, 0);
}