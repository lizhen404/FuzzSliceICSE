#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/core_namemap.c"
// 1 "../crypto/core_namemap.c" 2
// 10 "../crypto/core_namemap.c"
#include "/StaticSlicer/test_lib/openssl/include/internal/namemap.h"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/lhash.h"
// 11 "../crypto/core_namemap.c" 2

#include "/StaticSlicer/test_lib/openssl/include/crypto/lhash.h"
// 13 "../crypto/core_namemap.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/tsan_assist.h"
// 14 "../crypto/core_namemap.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/sizes.h"
// 15 "../crypto/core_namemap.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 16 "../crypto/core_namemap.c" 2





typedef struct {
char *name;
int number;
} NAMENUM_ENTRY;

struct lhash_st_NAMENUM_ENTRY { union lh_NAMENUM_ENTRY_dummy { void* d1; unsigned long d2; int d3; } dummy; }; static unsigned long lh_NAMENUM_ENTRY_hfn_thunk(const void *data, OPENSSL_LH_HASHFUNC hfn) { unsigned long (*hfn_conv)(const NAMENUM_ENTRY *) = (unsigned long (*)(const NAMENUM_ENTRY *))hfn; return hfn_conv((const NAMENUM_ENTRY *)data); } static int lh_NAMENUM_ENTRY_cfn_thunk(const void *da, const void *db, OPENSSL_LH_COMPFUNC cfn) { int (*cfn_conv)(const NAMENUM_ENTRY *, const NAMENUM_ENTRY *) = (int (*)(const NAMENUM_ENTRY *, const NAMENUM_ENTRY *))cfn; return cfn_conv((const NAMENUM_ENTRY *)da, (const NAMENUM_ENTRY *)db); } static  inline void lh_NAMENUM_ENTRY_free(struct lhash_st_NAMENUM_ENTRY *lh) { OPENSSL_LH_free((OPENSSL_LHASH *)lh); }
static  inline void lh_NAMENUM_ENTRY_doall_thunk(void *node, OPENSSL_LH_DOALL_FUNC doall) { void (*doall_conv)(NAMENUM_ENTRY *) = (void (*)(NAMENUM_ENTRY *))doall; doall_conv((NAMENUM_ENTRY *)node); } static  inline void lh_NAMENUM_ENTRY_doall_arg_thunk(void *node, void *arg, OPENSSL_LH_DOALL_FUNCARG doall) { void (*doall_conv)(NAMENUM_ENTRY *, void *) = (void (*)(NAMENUM_ENTRY *, void *))doall; doall_conv((NAMENUM_ENTRY *)node, arg); } static  inline void lh_NAMENUM_ENTRY_doall(struct lhash_st_NAMENUM_ENTRY *lh, void (*doall)(NAMENUM_ENTRY *)) { OPENSSL_LH_doall((OPENSSL_LHASH *)lh, (OPENSSL_LH_DOALL_FUNC)doall); } static  inline struct lhash_st_NAMENUM_ENTRY * lh_NAMENUM_ENTRY_new(unsigned long (*hfn)(const NAMENUM_ENTRY *), int (*cfn)(const NAMENUM_ENTRY *, const NAMENUM_ENTRY *)) { return (struct lhash_st_NAMENUM_ENTRY *)OPENSSL_LH_set_thunks(OPENSSL_LH_new((OPENSSL_LH_HASHFUNC)hfn, (OPENSSL_LH_COMPFUNC)cfn), lh_NAMENUM_ENTRY_hfn_thunk, lh_NAMENUM_ENTRY_cfn_thunk, lh_NAMENUM_ENTRY_doall_thunk, lh_NAMENUM_ENTRY_doall_arg_thunk); }
struct lhash_st_NAMENUM_ENTRY;






struct ossl_namemap_st {

unsigned int stored:1;

CRYPTO_RWLOCK *lock;
struct lhash_st_NAMENUM_ENTRY *namenum;

_Atomic int max_number;
};



static unsigned long namenum_hash(const NAMENUM_ENTRY *n)
{
return ossl_lh_strcasehash(n->name);
}

static int namenum_cmp(const NAMENUM_ENTRY *a, const NAMENUM_ENTRY *b)
{
return OPENSSL_strcasecmp(a->name, b->name);
}

static void namenum_free(NAMENUM_ENTRY *n)
{
if (n != ((void*)0))
CRYPTO_free(n->name, "../crypto/core_namemap.c", 58);
CRYPTO_free(n, "../crypto/core_namemap.c", 59);
}



void *ossl_stored_namemap_new(OSSL_LIB_CTX *libctx)
{
OSSL_NAMEMAP *namemap = ossl_namemap_new();

if (namemap != ((void*)0))
namemap->stored = 1;

return namemap;
}

void ossl_stored_namemap_free(void *vnamemap)
{
OSSL_NAMEMAP *namemap = vnamemap;

if (namemap != ((void*)0)) {

namemap->stored = 0;
ossl_namemap_free(namemap);
}
}






struct lhash_st_NAMENUM_ENTRY;






struct num2name_data_st {
size_t idx;
const char *name;
};

#include "/StaticSlicer/test_lib/openssl/include/openssl/evp.h"
// 382 "../crypto/core_namemap.c" 2


OSSL_NAMEMAP *ossl_namemap_new(void)
{
OSSL_NAMEMAP *namemap;

if ((namemap = CRYPTO_zalloc(sizeof(*namemap), "../crypto/core_namemap.c", 515)) != ((void*)0)
&& (namemap->lock = CRYPTO_THREAD_lock_new()) != ((void*)0)
&& (namemap->namenum =
lh_NAMENUM_ENTRY_new(namenum_hash, namenum_cmp)) != ((void*)0))
return namemap;

ossl_namemap_free(namemap);
return ((void*)0);
}

void ossl_namemap_free(OSSL_NAMEMAP *namemap)
{
if (namemap == ((void*)0) || namemap->stored)
return;

lh_NAMENUM_ENTRY_doall(namemap->namenum, namenum_free);
lh_NAMENUM_ENTRY_free(namemap->namenum);

CRYPTO_THREAD_lock_free(namemap->lock);
CRYPTO_free(namemap, "../crypto/core_namemap.c", 534);
}