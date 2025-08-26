#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/encode_decode/decoder_pkey.c"
// 1 "../crypto/encode_decode/decoder_pkey.c" 2
// 10 "../crypto/encode_decode/decoder_pkey.c"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/core_names.h"
// 11 "../crypto/encode_decode/decoder_pkey.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/core_object.h"
// 12 "../crypto/encode_decode/decoder_pkey.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/provider.h"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/safestack.h"
// 13 "../crypto/encode_decode/decoder_pkey.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/evp.h"
// 14 "../crypto/encode_decode/decoder_pkey.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/ui.h"
// 15 "../crypto/encode_decode/decoder_pkey.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/decoder.h"
// 16 "../crypto/encode_decode/decoder_pkey.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/trace.h"
// 18 "../crypto/encode_decode/decoder_pkey.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/evp.h"
// 19 "../crypto/encode_decode/decoder_pkey.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/decoder.h"
// 20 "../crypto/encode_decode/decoder_pkey.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/evp/evp_local.h"
// 21 "../crypto/encode_decode/decoder_pkey.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/lhash.h"
// 22 "../crypto/encode_decode/decoder_pkey.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/encode_decode/encoder_local.h"
// 23 "../crypto/encode_decode/decoder_pkey.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/namemap.h"
// 24 "../crypto/encode_decode/decoder_pkey.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/sizes.h"
// 25 "../crypto/encode_decode/decoder_pkey.c" 2

struct stack_st_EVP_KEYMGMT; typedef int (*sk_EVP_KEYMGMT_compfunc)(const EVP_KEYMGMT * const *a, const EVP_KEYMGMT *const *b); typedef void (*sk_EVP_KEYMGMT_freefunc)(EVP_KEYMGMT *a); typedef EVP_KEYMGMT * (*sk_EVP_KEYMGMT_copyfunc)(const EVP_KEYMGMT *a);
struct decoder_pkey_data_st {
OSSL_LIB_CTX *libctx;
char *propq;
int selection;

struct stack_st_EVP_KEYMGMT *keymgmts;
char *object_type;
void **object;
};

struct collect_data_st {
OSSL_LIB_CTX *libctx;
OSSL_DECODER_CTX *ctx;

const char *keytype;
int keytype_id;
int sm2_id;
int total;
char error_occurred;
char keytype_resolved;

struct stack_st_EVP_KEYMGMT *keymgmts;
};

typedef struct {
char *input_type;
char *input_structure;
char *keytype;
int selection;
char *propquery;
OSSL_DECODER_CTX *template;
} DECODER_CACHE_ENTRY;

struct lhash_st_DECODER_CACHE_ENTRY { union lh_DECODER_CACHE_ENTRY_dummy { void* d1; unsigned long d2; int d3; } dummy; }; static unsigned long lh_DECODER_CACHE_ENTRY_hfn_thunk(const void *data, OPENSSL_LH_HASHFUNC hfn) { unsigned long (*hfn_conv)(const DECODER_CACHE_ENTRY *) = (unsigned long (*)(const DECODER_CACHE_ENTRY *))hfn; return hfn_conv((const DECODER_CACHE_ENTRY *)data); } static int lh_DECODER_CACHE_ENTRY_cfn_thunk(const void *da, const void *db, OPENSSL_LH_COMPFUNC cfn) { int (*cfn_conv)(const DECODER_CACHE_ENTRY *, const DECODER_CACHE_ENTRY *) = (int (*)(const DECODER_CACHE_ENTRY *, const DECODER_CACHE_ENTRY *))cfn; return cfn_conv((const DECODER_CACHE_ENTRY *)da, (const DECODER_CACHE_ENTRY *)db); } static  inline void lh_DECODER_CACHE_ENTRY_free(struct lhash_st_DECODER_CACHE_ENTRY *lh) { OPENSSL_LH_free((OPENSSL_LHASH *)lh); } static  inline void lh_DECODER_CACHE_ENTRY_flush(struct lhash_st_DECODER_CACHE_ENTRY *lh) { OPENSSL_LH_flush((OPENSSL_LHASH *)lh); }
static  inline void lh_DECODER_CACHE_ENTRY_doall_thunk(void *node, OPENSSL_LH_DOALL_FUNC doall) { void (*doall_conv)(DECODER_CACHE_ENTRY *) = (void (*)(DECODER_CACHE_ENTRY *))doall; doall_conv((DECODER_CACHE_ENTRY *)node); } static  inline void lh_DECODER_CACHE_ENTRY_doall_arg_thunk(void *node, void *arg, OPENSSL_LH_DOALL_FUNCARG doall) { void (*doall_conv)(DECODER_CACHE_ENTRY *, void *) = (void (*)(DECODER_CACHE_ENTRY *, void *))doall; doall_conv((DECODER_CACHE_ENTRY *)node, arg); } static  inline void lh_DECODER_CACHE_ENTRY_doall(struct lhash_st_DECODER_CACHE_ENTRY *lh, void (*doall)(DECODER_CACHE_ENTRY *)) { OPENSSL_LH_doall((OPENSSL_LHASH *)lh, (OPENSSL_LH_DOALL_FUNC)doall); } static  inline struct lhash_st_DECODER_CACHE_ENTRY * lh_DECODER_CACHE_ENTRY_new(unsigned long (*hfn)(const DECODER_CACHE_ENTRY *), int (*cfn)(const DECODER_CACHE_ENTRY *, const DECODER_CACHE_ENTRY *)) { return (struct lhash_st_DECODER_CACHE_ENTRY *)OPENSSL_LH_set_thunks(OPENSSL_LH_new((OPENSSL_LH_HASHFUNC)hfn, (OPENSSL_LH_COMPFUNC)cfn), lh_DECODER_CACHE_ENTRY_hfn_thunk, lh_DECODER_CACHE_ENTRY_cfn_thunk, lh_DECODER_CACHE_ENTRY_doall_thunk, lh_DECODER_CACHE_ENTRY_doall_arg_thunk); }
struct lhash_st_DECODER_CACHE_ENTRY;

typedef struct {
CRYPTO_RWLOCK *lock;
struct lhash_st_DECODER_CACHE_ENTRY *hashtable;
} DECODER_CACHE;

static void decoder_cache_entry_free(DECODER_CACHE_ENTRY *entry)
{
if (entry == ((void*)0))
return;
CRYPTO_free(entry->input_type, "../crypto/encode_decode/decoder_pkey.c", 608);
CRYPTO_free(entry->input_structure, "../crypto/encode_decode/decoder_pkey.c", 609);
CRYPTO_free(entry->keytype, "../crypto/encode_decode/decoder_pkey.c", 610);
CRYPTO_free(entry->propquery, "../crypto/encode_decode/decoder_pkey.c", 611);
OSSL_DECODER_CTX_free(entry->template);
CRYPTO_free(entry, "../crypto/encode_decode/decoder_pkey.c", 613);
}

static unsigned long decoder_cache_entry_hash(const DECODER_CACHE_ENTRY *cache)
{
unsigned long hash = 17;

hash = (hash * 23)
+ (cache->propquery == ((void*)0)
? 0 : ossl_lh_strcasehash(cache->propquery));
hash = (hash * 23)
+ (cache->input_structure == ((void*)0)
? 0 : ossl_lh_strcasehash(cache->input_structure));
hash = (hash * 23)
+ (cache->input_type == ((void*)0)
? 0 : ossl_lh_strcasehash(cache->input_type));
hash = (hash * 23)
+ (cache->keytype == ((void*)0)
? 0 : ossl_lh_strcasehash(cache->keytype));

hash ^= cache->selection;

return hash;
}

static inline int nullstrcmp(const char *a, const char *b, int casecmp)
{
if (a == ((void*)0) || b == ((void*)0)) {
if (a == ((void*)0)) {
if (b == ((void*)0))
return 0;
else
return 1;
} else {
return -1;
}
} else {
if (casecmp)
return OPENSSL_strcasecmp(a, b);
else
return strcmp(a, b);
}
}

static int decoder_cache_entry_cmp(const DECODER_CACHE_ENTRY *a,
const DECODER_CACHE_ENTRY *b)
{
int cmp;

if (a->selection != b->selection)
return (a->selection < b->selection) ? -1 : 1;

cmp = nullstrcmp(a->keytype, b->keytype, 1);
if (cmp != 0)
return cmp;

cmp = nullstrcmp(a->input_type, b->input_type, 1);
if (cmp != 0)
return cmp;

cmp = nullstrcmp(a->input_structure, b->input_structure, 1);
if (cmp != 0)
return cmp;

cmp = nullstrcmp(a->propquery, b->propquery, 0);

return cmp;
}

void *ossl_decoder_cache_new(OSSL_LIB_CTX *ctx)
{
DECODER_CACHE *cache = CRYPTO_malloc(sizeof(*cache), "../crypto/encode_decode/decoder_pkey.c", 684);

if (cache == ((void*)0))
return ((void*)0);

cache->lock = CRYPTO_THREAD_lock_new();
if (cache->lock == ((void*)0)) {
CRYPTO_free(cache, "../crypto/encode_decode/decoder_pkey.c", 691);
return ((void*)0);
}
cache->hashtable = lh_DECODER_CACHE_ENTRY_new(decoder_cache_entry_hash,
decoder_cache_entry_cmp);
if (cache->hashtable == ((void*)0)) {
CRYPTO_THREAD_lock_free(cache->lock);
CRYPTO_free(cache, "../crypto/encode_decode/decoder_pkey.c", 698);
return ((void*)0);
}

return cache;
}

void ossl_decoder_cache_free(void *vcache)
{
DECODER_CACHE *cache = (DECODER_CACHE *)vcache;

lh_DECODER_CACHE_ENTRY_doall(cache->hashtable, decoder_cache_entry_free);
lh_DECODER_CACHE_ENTRY_free(cache->hashtable);
CRYPTO_THREAD_lock_free(cache->lock);
CRYPTO_free(cache, "../crypto/encode_decode/decoder_pkey.c", 712);
}





int ossl_decoder_cache_flush(OSSL_LIB_CTX *libctx)
{
DECODER_CACHE *cache
= ossl_lib_ctx_get_data(libctx, 20);

if (cache == ((void*)0))
return 0;


if (!CRYPTO_THREAD_write_lock(cache->lock)) {
(ERR_new(), ERR_set_debug("../crypto/encode_decode/decoder_pkey.c",729,__func__), ERR_set_error)((60),((60 | (0x2 << 18L))),((void*)0));
return 0;
}

lh_DECODER_CACHE_ENTRY_doall(cache->hashtable, decoder_cache_entry_free);
lh_DECODER_CACHE_ENTRY_flush(cache->hashtable);

CRYPTO_THREAD_unlock(cache->lock);
return 1;
}
