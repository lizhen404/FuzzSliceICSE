#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/property/defn_cache.c"
// 1 "../crypto/property/defn_cache.c" 2
// 11 "../crypto/property/defn_cache.c"
// 12 "../crypto/property/defn_cache.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/err.h"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/lhash.h"
// 13 "../crypto/property/defn_cache.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/propertyerr.h"
// 15 "../crypto/property/defn_cache.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/property.h"
// 16 "../crypto/property/defn_cache.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/core.h"
// 17 "../crypto/property/defn_cache.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/property/property_local.h"
// 18 "../crypto/property/defn_cache.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 19 "../crypto/property/defn_cache.c" 2







typedef struct {
const char *prop;
OSSL_PROPERTY_LIST *defn;
char body[1];
} PROPERTY_DEFN_ELEM;

struct lhash_st_PROPERTY_DEFN_ELEM { union lh_PROPERTY_DEFN_ELEM_dummy { void* d1; unsigned long d2; int d3; } dummy; }; static unsigned long lh_PROPERTY_DEFN_ELEM_hfn_thunk(const void *data, OPENSSL_LH_HASHFUNC hfn) { unsigned long (*hfn_conv)(const PROPERTY_DEFN_ELEM *) = (unsigned long (*)(const PROPERTY_DEFN_ELEM *))hfn; return hfn_conv((const PROPERTY_DEFN_ELEM *)data); } static int lh_PROPERTY_DEFN_ELEM_cfn_thunk(const void *da, const void *db, OPENSSL_LH_COMPFUNC cfn) { int (*cfn_conv)(const PROPERTY_DEFN_ELEM *, const PROPERTY_DEFN_ELEM *) = (int (*)(const PROPERTY_DEFN_ELEM *, const PROPERTY_DEFN_ELEM *))cfn; return cfn_conv((const PROPERTY_DEFN_ELEM *)da, (const PROPERTY_DEFN_ELEM *)db); } static  inline void lh_PROPERTY_DEFN_ELEM_free(struct lhash_st_PROPERTY_DEFN_ELEM *lh) { OPENSSL_LH_free((OPENSSL_LHASH *)lh); }
static  inline void lh_PROPERTY_DEFN_ELEM_doall_thunk(void *node, OPENSSL_LH_DOALL_FUNC doall) { void (*doall_conv)(PROPERTY_DEFN_ELEM *) = (void (*)(PROPERTY_DEFN_ELEM *))doall; doall_conv((PROPERTY_DEFN_ELEM *)node); } static  inline void lh_PROPERTY_DEFN_ELEM_doall_arg_thunk(void *node, void *arg, OPENSSL_LH_DOALL_FUNCARG doall) { void (*doall_conv)(PROPERTY_DEFN_ELEM *, void *) = (void (*)(PROPERTY_DEFN_ELEM *, void *))doall; doall_conv((PROPERTY_DEFN_ELEM *)node, arg); } static  inline void lh_PROPERTY_DEFN_ELEM_doall(struct lhash_st_PROPERTY_DEFN_ELEM *lh, void (*doall)(PROPERTY_DEFN_ELEM *)) { OPENSSL_LH_doall((OPENSSL_LHASH *)lh, (OPENSSL_LH_DOALL_FUNC)doall); } static  inline struct lhash_st_PROPERTY_DEFN_ELEM * lh_PROPERTY_DEFN_ELEM_new(unsigned long (*hfn)(const PROPERTY_DEFN_ELEM *), int (*cfn)(const PROPERTY_DEFN_ELEM *, const PROPERTY_DEFN_ELEM *)) { return (struct lhash_st_PROPERTY_DEFN_ELEM *)OPENSSL_LH_set_thunks(OPENSSL_LH_new((OPENSSL_LH_HASHFUNC)hfn, (OPENSSL_LH_COMPFUNC)cfn), lh_PROPERTY_DEFN_ELEM_hfn_thunk, lh_PROPERTY_DEFN_ELEM_cfn_thunk, lh_PROPERTY_DEFN_ELEM_doall_thunk, lh_PROPERTY_DEFN_ELEM_doall_arg_thunk); }
struct lhash_st_PROPERTY_DEFN_ELEM;

static unsigned long property_defn_hash(const PROPERTY_DEFN_ELEM *a)
{
return OPENSSL_LH_strhash(a->prop);
}

static int property_defn_cmp(const PROPERTY_DEFN_ELEM *a,
const PROPERTY_DEFN_ELEM *b)
{
return strcmp(a->prop, b->prop);
}

static void property_defn_free(PROPERTY_DEFN_ELEM *elem)
{
ossl_property_free(elem->defn);
CRYPTO_free(elem, "../crypto/property/defn_cache.c", 48);
}

void ossl_property_defns_free(void *vproperty_defns)
{
struct lhash_st_PROPERTY_DEFN_ELEM *property_defns = vproperty_defns;

if (property_defns != ((void*)0)) {
lh_PROPERTY_DEFN_ELEM_doall(property_defns,
&property_defn_free);
lh_PROPERTY_DEFN_ELEM_free(property_defns);
}
}

void *ossl_property_defns_new(OSSL_LIB_CTX *ctx) {
return lh_PROPERTY_DEFN_ELEM_new(&property_defn_hash, &property_defn_cmp);
}
