#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/property/property.c"
// 1 "../crypto/property/property.c" 2
// 11 "../crypto/property/property.c"
// 12 "../crypto/property/property.c" 2
#include <stdarg.h>
// 13 "../crypto/property/property.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/crypto.h"
// 15 "../crypto/property/property.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/core.h"
// 16 "../crypto/property/property.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/property.h"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/lhash.h"
// 17 "../crypto/property/property.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/provider.h"
// 18 "../crypto/property/property.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/tsan_assist.h"
// 19 "../crypto/property/property.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/ctype.h"
// 20 "../crypto/property/property.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/rand.h"
// 22 "../crypto/property/property.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/thread_once.h"
// 23 "../crypto/property/property.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/lhash.h"
// 24 "../crypto/property/property.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/sparse_array.h"
// 25 "../crypto/property/property.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/property/property_local.h"
// 26 "../crypto/property/property.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 27 "../crypto/property/property.c" 2








typedef struct {
void *method;
int (*up_ref)(void *);
void (*free)(void *);
} METHOD;

typedef struct {
const OSSL_PROVIDER *provider;
OSSL_PROPERTY_LIST *properties;
METHOD method;
} IMPLEMENTATION;

struct stack_st_IMPLEMENTATION; typedef int (*sk_IMPLEMENTATION_compfunc)(const IMPLEMENTATION * const *a, const IMPLEMENTATION *const *b); typedef void (*sk_IMPLEMENTATION_freefunc)(IMPLEMENTATION *a); typedef IMPLEMENTATION * (*sk_IMPLEMENTATION_copyfunc)(const IMPLEMENTATION *a); static  inline int sk_IMPLEMENTATION_num(const struct stack_st_IMPLEMENTATION *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static  inline IMPLEMENTATION *sk_IMPLEMENTATION_value(const struct stack_st_IMPLEMENTATION *sk, int idx) { return (IMPLEMENTATION *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); }
static  inline IMPLEMENTATION *sk_IMPLEMENTATION_delete(struct stack_st_IMPLEMENTATION *sk, int i) { return (IMPLEMENTATION *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); }
static  inline void sk_IMPLEMENTATION_pop_free(struct stack_st_IMPLEMENTATION *sk, sk_IMPLEMENTATION_freefunc freefunc) { OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); }
typedef struct {
const OSSL_PROVIDER *provider;
const char *query;
METHOD method;
char body[1];
} QUERY;

struct lhash_st_QUERY { union lh_QUERY_dummy { void* d1; unsigned long d2; int d3; } dummy; };
static  inline void lh_QUERY_free(struct lhash_st_QUERY *lh) { OPENSSL_LH_free((OPENSSL_LHASH *)lh); } static  inline void lh_QUERY_flush(struct lhash_st_QUERY *lh) { OPENSSL_LH_flush((OPENSSL_LHASH *)lh); }
static  inline unsigned long lh_QUERY_num_items(struct lhash_st_QUERY *lh) { return OPENSSL_LH_num_items((OPENSSL_LHASH *)lh); }
static  inline void lh_QUERY_doall(struct lhash_st_QUERY *lh, void (*doall)(QUERY *)) { OPENSSL_LH_doall((OPENSSL_LHASH *)lh, (OPENSSL_LH_DOALL_FUNC)doall); }
struct lhash_st_QUERY;

typedef struct {
int nid;
struct stack_st_IMPLEMENTATION *impls;
struct lhash_st_QUERY *cache;
} ALGORITHM;

struct ossl_method_store_st {
OSSL_LIB_CTX *ctx;
struct sparse_array_st_ALGORITHM *algs;





CRYPTO_RWLOCK *lock;






CRYPTO_RWLOCK *biglock;




size_t cache_nelem;


int cache_need_flush;
};

struct sparse_array_st_ALGORITHM; static  inline struct sparse_array_st_ALGORITHM * ossl_sa_ALGORITHM_new(void) { return (struct sparse_array_st_ALGORITHM *)ossl_sa_new(); } static  inline void ossl_sa_ALGORITHM_free(struct sparse_array_st_ALGORITHM *sa) { ossl_sa_free((OPENSSL_SA *)sa); }
static  inline void ossl_sa_ALGORITHM_doall_arg(const struct sparse_array_st_ALGORITHM *sa, void (*leaf)(ossl_uintmax_t, ALGORITHM *, void *), void *arg) { ossl_sa_doall_arg((OPENSSL_SA *)sa, (void (*)(ossl_uintmax_t, void *, void *))leaf, arg); }
static  inline int ossl_sa_ALGORITHM_set(struct sparse_array_st_ALGORITHM *sa, ossl_uintmax_t n, ALGORITHM *val) { return ossl_sa_set((OPENSSL_SA *)sa, n, (void *)val); } struct sparse_array_st_ALGORITHM;

typedef struct ossl_global_properties_st {
OSSL_PROPERTY_LIST *list;

unsigned int no_mirrored : 1;

} OSSL_GLOBAL_PROPERTIES;

static void ossl_method_cache_flush_alg(OSSL_METHOD_STORE *store,
ALGORITHM *alg);
void ossl_ctx_global_properties_free(void *vglobp)
{
OSSL_GLOBAL_PROPERTIES *globp = vglobp;

if (globp != ((void*)0)) {
ossl_property_free(globp->list);
CRYPTO_free(globp, "../crypto/property/property.c", 117);
}
}

void *ossl_ctx_global_properties_new(OSSL_LIB_CTX *ctx)
{
return CRYPTO_zalloc(sizeof(OSSL_GLOBAL_PROPERTIES), "../crypto/property/property.c", 123);
}

static void ossl_method_free(METHOD *method)
{
(*method->free)(method->method);
}

static int ossl_property_write_lock(OSSL_METHOD_STORE *p)
{
return p != ((void*)0) ? CRYPTO_THREAD_write_lock(p->lock) : 0;
}

static int ossl_property_unlock(OSSL_METHOD_STORE *p)
{
return p != 0 ? CRYPTO_THREAD_unlock(p->lock) : 0;
}

static void impl_free(IMPLEMENTATION *impl)
{
if (impl != ((void*)0)) {
ossl_method_free(&impl->method);
CRYPTO_free(impl, "../crypto/property/property.c", 204);
}
}

static void impl_cache_free(QUERY *elem)
{
if (elem != ((void*)0)) {
ossl_method_free(&elem->method);
CRYPTO_free(elem, "../crypto/property/property.c", 212);
}
}

static void impl_cache_flush_alg(ossl_uintmax_t idx, ALGORITHM *alg)
{
lh_QUERY_doall(alg->cache, &impl_cache_free);
lh_QUERY_flush(alg->cache);
}

static void alg_cleanup(ossl_uintmax_t idx, ALGORITHM *a, void *arg)
{
OSSL_METHOD_STORE *store = arg;

if (a != ((void*)0)) {
sk_IMPLEMENTATION_pop_free(a->impls, &impl_free);
lh_QUERY_doall(a->cache, &impl_cache_free);
lh_QUERY_free(a->cache);
CRYPTO_free(a, "../crypto/property/property.c", 230);
}
if (store != ((void*)0))
ossl_sa_ALGORITHM_set(store->algs, idx, ((void*)0));
}





OSSL_METHOD_STORE *ossl_method_store_new(OSSL_LIB_CTX *ctx)
{
OSSL_METHOD_STORE *res;

res = CRYPTO_zalloc(sizeof(*res), "../crypto/property/property.c", 244);
if (res != ((void*)0)) {
res->ctx = ctx;
if ((res->algs = ossl_sa_ALGORITHM_new()) == ((void*)0)
|| (res->lock = CRYPTO_THREAD_lock_new()) == ((void*)0)
|| (res->biglock = CRYPTO_THREAD_lock_new()) == ((void*)0)) {
ossl_method_store_free(res);
return ((void*)0);
}
}
return res;
}

void ossl_method_store_free(OSSL_METHOD_STORE *store)
{
if (store != ((void*)0)) {
if (store->algs != ((void*)0))
ossl_sa_ALGORITHM_doall_arg(store->algs, &alg_cleanup, store);
ossl_sa_ALGORITHM_free(store->algs);
CRYPTO_THREAD_lock_free(store->lock);
CRYPTO_THREAD_lock_free(store->biglock);
CRYPTO_free(store, "../crypto/property/property.c", 265);
}
}

struct alg_cleanup_by_provider_data_st {
OSSL_METHOD_STORE *store;
const OSSL_PROVIDER *prov;
};

static void
alg_cleanup_by_provider(ossl_uintmax_t idx, ALGORITHM *alg, void *arg)
{
struct alg_cleanup_by_provider_data_st *data = arg;
int i, count;





for (count = 0, i = sk_IMPLEMENTATION_num(alg->impls); i-- > 0;) {
IMPLEMENTATION *impl = sk_IMPLEMENTATION_value(alg->impls, i);

if (impl->provider == data->prov) {
impl_free(impl);
(void)sk_IMPLEMENTATION_delete(alg->impls, i);
count++;
}
}







if (count > 0)
ossl_method_cache_flush_alg(data->store, alg);
}

int ossl_method_store_remove_all_provided(OSSL_METHOD_STORE *store,
const OSSL_PROVIDER *prov)
{
struct alg_cleanup_by_provider_data_st data;

if (!ossl_property_write_lock(store))
return 0;
data.prov = prov;
data.store = store;
ossl_sa_ALGORITHM_doall_arg(store->algs, &alg_cleanup_by_provider, &data);
ossl_property_unlock(store);
return 1;
}

struct alg_do_each_data_st {
void (*fn)(int id, void *method, void *fnarg);
void *fnarg;
};

static void ossl_method_cache_flush_alg(OSSL_METHOD_STORE *store,
ALGORITHM *alg)
{
store->cache_nelem -= lh_QUERY_num_items(alg->cache);
impl_cache_flush_alg(0, alg);
}

struct lhash_st_QUERY;
// 619 "../crypto/property/property.c"