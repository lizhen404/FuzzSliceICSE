#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/provider_core.c"
// 1 "../crypto/provider_core.c" 2
// 10 "../crypto/provider_core.c"
#include <assert.h>
// 11 "../crypto/provider_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/core.h"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/opensslv.h"
// 12 "../crypto/provider_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/core_dispatch.h"
// 13 "../crypto/provider_core.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/core_names.h"
// 14 "../crypto/provider_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/provider.h"
// 15 "../crypto/provider_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/params.h"
// 16 "../crypto/provider_core.c" 2

#include "/StaticSlicer/test_lib/openssl/include/crypto/cryptlib.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/nelem.h"
// 18 "../crypto/provider_core.c" 2

#include "/StaticSlicer/test_lib/openssl/include/crypto/decoder.h"
// 20 "../crypto/provider_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/encoder.h"
// 21 "../crypto/provider_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/store.h"
// 22 "../crypto/provider_core.c" 2

#include "/StaticSlicer/test_lib/openssl/include/crypto/evp.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/refcount.h"
// 24 "../crypto/provider_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/rand.h"
// 25 "../crypto/provider_core.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/thread_once.h"
// 27 "../crypto/provider_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/provider.h"
// 28 "../crypto/provider_core.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/bio.h"
// 30 "../crypto/provider_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/core.h"
// 31 "../crypto/provider_core.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/provider_local.h"
// 32 "../crypto/provider_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 33 "../crypto/provider_core.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/self_test.h"
// 35 "../crypto/provider_core.c" 2
// 119 "../crypto/provider_core.c"
typedef struct {
OSSL_PROVIDER *prov;
int (*create_cb)(const OSSL_CORE_HANDLE *provider, void *cbdata);
int (*remove_cb)(const OSSL_CORE_HANDLE *provider, void *cbdata);
int (*global_props_cb)(const char *props, void *cbdata);
void *cbdata;
} OSSL_PROVIDER_CHILD_CB;
struct stack_st_OSSL_PROVIDER_CHILD_CB; typedef int (*sk_OSSL_PROVIDER_CHILD_CB_compfunc)(const OSSL_PROVIDER_CHILD_CB * const *a, const OSSL_PROVIDER_CHILD_CB *const *b); typedef void (*sk_OSSL_PROVIDER_CHILD_CB_freefunc)(OSSL_PROVIDER_CHILD_CB *a); typedef OSSL_PROVIDER_CHILD_CB * (*sk_OSSL_PROVIDER_CHILD_CB_copyfunc)(const OSSL_PROVIDER_CHILD_CB *a); static  inline int sk_OSSL_PROVIDER_CHILD_CB_num(const struct stack_st_OSSL_PROVIDER_CHILD_CB *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static  inline OSSL_PROVIDER_CHILD_CB *sk_OSSL_PROVIDER_CHILD_CB_value(const struct stack_st_OSSL_PROVIDER_CHILD_CB *sk, int idx) { return (OSSL_PROVIDER_CHILD_CB *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); }
static  inline struct stack_st_OSSL_PROVIDER_CHILD_CB *sk_OSSL_PROVIDER_CHILD_CB_new_null(void) { return (struct stack_st_OSSL_PROVIDER_CHILD_CB *)OPENSSL_sk_new_null(); }
static  inline void sk_OSSL_PROVIDER_CHILD_CB_pop_free(struct stack_st_OSSL_PROVIDER_CHILD_CB *sk, sk_OSSL_PROVIDER_CHILD_CB_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); }
struct provider_store_st;

struct ossl_provider_st {

unsigned int flag_initialized:1;
unsigned int flag_activated:1;


CRYPTO_RWLOCK *flag_lock;


CRYPTO_REF_COUNT refcnt;
CRYPTO_RWLOCK *activatecnt_lock;
int activatecnt;
char *name;
char *path;
DSO *module;
OSSL_provider_init_fn *init_function;
struct stack_st_INFOPAIR *parameters;
OSSL_LIB_CTX *libctx;
struct provider_store_st *store;





int error_lib;

ERR_STRING_DATA *error_strings;




OSSL_FUNC_provider_teardown_fn *teardown;
OSSL_FUNC_provider_gettable_params_fn *gettable_params;
OSSL_FUNC_provider_get_params_fn *get_params;
OSSL_FUNC_provider_get_capabilities_fn *get_capabilities;
OSSL_FUNC_provider_self_test_fn *self_test;
OSSL_FUNC_provider_query_operation_fn *query_operation;
OSSL_FUNC_provider_unquery_operation_fn *unquery_operation;





unsigned char *operation_bits;
size_t operation_bits_sz;
CRYPTO_RWLOCK *opbits_lock;



const OSSL_CORE_HANDLE *handle;
unsigned int ischild:1;



void *provctx;
const OSSL_DISPATCH *dispatch;
};
struct stack_st_OSSL_PROVIDER; typedef int (*sk_OSSL_PROVIDER_compfunc)(const OSSL_PROVIDER * const *a, const OSSL_PROVIDER *const *b); typedef void (*sk_OSSL_PROVIDER_freefunc)(OSSL_PROVIDER *a); typedef OSSL_PROVIDER * (*sk_OSSL_PROVIDER_copyfunc)(const OSSL_PROVIDER *a);
static  inline struct stack_st_OSSL_PROVIDER *sk_OSSL_PROVIDER_new(sk_OSSL_PROVIDER_compfunc compare) { return (struct stack_st_OSSL_PROVIDER *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); }
static  inline void sk_OSSL_PROVIDER_pop_free(struct stack_st_OSSL_PROVIDER *sk, sk_OSSL_PROVIDER_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); }
static int ossl_provider_cmp(const OSSL_PROVIDER * const *a,
const OSSL_PROVIDER * const *b)
{
return strcmp((*a)->name, (*b)->name);
}
// 214 "../crypto/provider_core.c"
struct provider_store_st {
OSSL_LIB_CTX *libctx;
struct stack_st_OSSL_PROVIDER *providers;
struct stack_st_OSSL_PROVIDER_CHILD_CB *child_cbs;
CRYPTO_RWLOCK *default_path_lock;
CRYPTO_RWLOCK *lock;
char *default_path;
OSSL_PROVIDER_INFO *provinfo;
size_t numprovinfo;
size_t provinfosz;
unsigned int use_fallbacks:1;
unsigned int freeing:1;
};







static void provider_deactivate_free(OSSL_PROVIDER *prov)
{
if (prov->flag_activated)
ossl_provider_deactivate(prov, 1);
ossl_provider_free(prov);
}


static void ossl_provider_child_cb_free(OSSL_PROVIDER_CHILD_CB *cb)
{
CRYPTO_free(cb, "../crypto/provider_core.c", 244);
}


static void infopair_free(INFOPAIR *pair)
{
CRYPTO_free(pair->name, "../crypto/provider_core.c", 250);
CRYPTO_free(pair->value, "../crypto/provider_core.c", 251);
CRYPTO_free(pair, "../crypto/provider_core.c", 252);
}

void ossl_provider_info_clear(OSSL_PROVIDER_INFO *info)
{
CRYPTO_free(info->name, "../crypto/provider_core.c", 280);
CRYPTO_free(info->path, "../crypto/provider_core.c", 281);
sk_INFOPAIR_pop_free(info->parameters, infopair_free);
}

void ossl_provider_store_free(void *vstore)
{
struct provider_store_st *store = vstore;
size_t i;

if (store == ((void*)0))
return;
store->freeing = 1;
CRYPTO_free(store->default_path, "../crypto/provider_core.c", 293);
sk_OSSL_PROVIDER_pop_free(store->providers, provider_deactivate_free);

sk_OSSL_PROVIDER_CHILD_CB_pop_free(store->child_cbs,
ossl_provider_child_cb_free);

CRYPTO_THREAD_lock_free(store->default_path_lock);
CRYPTO_THREAD_lock_free(store->lock);
for (i = 0; i < store->numprovinfo; i++)
ossl_provider_info_clear(&store->provinfo[i]);
CRYPTO_free(store->provinfo, "../crypto/provider_core.c", 303);
CRYPTO_free(store, "../crypto/provider_core.c", 304);
}

void *ossl_provider_store_new(OSSL_LIB_CTX *ctx)
{
struct provider_store_st *store = CRYPTO_zalloc(sizeof(*store), "../crypto/provider_core.c", 309);

if (store == ((void*)0)
|| (store->providers = sk_OSSL_PROVIDER_new(ossl_provider_cmp)) == ((void*)0)
|| (store->default_path_lock = CRYPTO_THREAD_lock_new()) == ((void*)0)

|| (store->child_cbs = sk_OSSL_PROVIDER_CHILD_CB_new_null()) == ((void*)0)

|| (store->lock = CRYPTO_THREAD_lock_new()) == ((void*)0)) {
ossl_provider_store_free(store);
return ((void*)0);
}
store->libctx = ctx;
store->use_fallbacks = 1;

return store;
}

static struct provider_store_st *get_provider_store(OSSL_LIB_CTX *libctx)
{
struct provider_store_st *store = ((void*)0);

store = ossl_lib_ctx_get_data(libctx, 1);
if (store == ((void*)0))
(ERR_new(), ERR_set_debug("../crypto/provider_core.c",333,__func__), ERR_set_error)((15),((259|((0x1 << 18L)|(0x2 << 18L)))),((void*)0));
return store;
}

void ossl_provider_free(OSSL_PROVIDER *prov)
{
if (prov != ((void*)0)) {
int ref = 0;

CRYPTO_DOWN_REF(&prov->refcnt, &ref);
// 711 "../crypto/provider_core.c"
if (ref == 0) {
if (prov->flag_initialized) {
ossl_provider_teardown(prov);


if (prov->error_strings != ((void*)0)) {
ERR_unload_strings(prov->error_lib, prov->error_strings);
CRYPTO_free(prov->error_strings, "../crypto/provider_core.c", 718);
prov->error_strings = ((void*)0);
}


CRYPTO_free(prov->operation_bits, "../crypto/provider_core.c", 723);
prov->operation_bits = ((void*)0);
prov->operation_bits_sz = 0;
prov->flag_initialized = 0;
}







ossl_init_thread_deregister(prov);
DSO_free(prov->module);

CRYPTO_free(prov->name, "../crypto/provider_core.c", 738);
CRYPTO_free(prov->path, "../crypto/provider_core.c", 739);
sk_INFOPAIR_pop_free(prov->parameters, infopair_free);
CRYPTO_THREAD_lock_free(prov->opbits_lock);
CRYPTO_THREAD_lock_free(prov->flag_lock);
CRYPTO_THREAD_lock_free(prov->activatecnt_lock);
CRYPTO_FREE_REF(&prov->refcnt);
CRYPTO_free(prov, "../crypto/provider_core.c", 745);
}

else if (prov->ischild) {
ossl_provider_free_parent(prov, 0);
}

}
}


// 820 "../crypto/provider_core.c"


static int provider_deactivate(OSSL_PROVIDER *prov, int upcalls,
int removechildren)
{
int count;
struct provider_store_st *store;

int freeparent = 0;

int lock = 1;

if (!__builtin_expect(!!((prov != ((void*)0)) != 0), 1))
return -1;





store = get_provider_store(prov->libctx);
if (store == ((void*)0))
lock = 0;

if (lock && !CRYPTO_THREAD_read_lock(store->lock))
return -1;
if (lock && !CRYPTO_THREAD_write_lock(prov->flag_lock)) {
CRYPTO_THREAD_unlock(store->lock);
return -1;
}

CRYPTO_atomic_add(&prov->activatecnt, -1, &count, prov->activatecnt_lock);

if (count >= 1 && prov->ischild && upcalls) {






freeparent = 1;
}


if (count < 1)
prov->flag_activated = 0;

else
removechildren = 0;



if (removechildren && store != ((void*)0)) {
int i, max = sk_OSSL_PROVIDER_CHILD_CB_num(store->child_cbs);
OSSL_PROVIDER_CHILD_CB *child_cb;

for (i = 0; i < max; i++) {
child_cb = sk_OSSL_PROVIDER_CHILD_CB_value(store->child_cbs, i);
child_cb->remove_cb((OSSL_CORE_HANDLE *)prov, child_cb->cbdata);
}
}

if (lock) {
CRYPTO_THREAD_unlock(prov->flag_lock);
CRYPTO_THREAD_unlock(store->lock);





if (count < 1)
ossl_decoder_cache_flush(prov->libctx);

}

if (freeparent)
ossl_provider_free_parent(prov, 1);



return count;
}





static int provider_remove_store_methods(OSSL_PROVIDER *prov)
{
struct provider_store_st *store;
int freeing;

if ((store = get_provider_store(prov->libctx)) == ((void*)0))
return 0;

if (!CRYPTO_THREAD_read_lock(store->lock))
return 0;
freeing = store->freeing;
CRYPTO_THREAD_unlock(store->lock);

if (!freeing) {
int acc;

if (!CRYPTO_THREAD_write_lock(prov->opbits_lock))
return 0;
CRYPTO_free(prov->operation_bits, "../crypto/provider_core.c", 1270);
prov->operation_bits = ((void*)0);
prov->operation_bits_sz = 0;
CRYPTO_THREAD_unlock(prov->opbits_lock);

acc = evp_method_store_remove_all_provided(prov)

+ ossl_encoder_store_remove_all_provided(prov)
+ ossl_decoder_store_remove_all_provided(prov)
+ ossl_store_loader_store_remove_all_provided(prov)

;


return acc == 4;



}
return 1;
}

int ossl_provider_deactivate(OSSL_PROVIDER *prov, int removechildren)
{
int count;

if (prov == ((void*)0)
|| (count = provider_deactivate(prov, 1, removechildren)) < 0)
return 0;
return count == 0 ? provider_remove_store_methods(prov) : 1;
}

OSSL_LIB_CTX *ossl_provider_libctx(const OSSL_PROVIDER *prov)
{
return prov != ((void*)0) ? prov->libctx : ((void*)0);
}


void ossl_provider_teardown(const OSSL_PROVIDER *prov)
{
if (prov->teardown != ((void*)0)

&& !prov->ischild

)
prov->teardown(prov->provctx);
}

const OSSL_CORE_HANDLE *ossl_provider_get_parent(OSSL_PROVIDER *prov)
{
return prov->handle;
}

// 1893 "../crypto/provider_core.c"







































OSSL_FUNC_CRYPTO_zalloc_fn CRYPTO_zalloc;
OSSL_FUNC_CRYPTO_free_fn CRYPTO_free;





















// 2046 "../crypto/provider_core.c"
