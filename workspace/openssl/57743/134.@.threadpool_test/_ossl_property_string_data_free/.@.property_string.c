#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/property/property_string.c"
// 1 "../crypto/property/property_string.c" 2
// 11 "../crypto/property/property_string.c"
// 12 "../crypto/property/property_string.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/crypto.h"
// 13 "../crypto/property/property_string.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/lhash.h"
// 14 "../crypto/property/property_string.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/lhash.h"
// 15 "../crypto/property/property_string.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/property/property_local.h"
// 16 "../crypto/property/property_string.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 17 "../crypto/property/property_string.c" 2
// 29 "../crypto/property/property_string.c"
typedef struct {
const char *s;
OSSL_PROPERTY_IDX idx;
char body[1];
} PROPERTY_STRING;

struct lhash_st_PROPERTY_STRING { union lh_PROPERTY_STRING_dummy { void* d1; unsigned long d2; int d3; } dummy; }; static unsigned long lh_PROPERTY_STRING_hfn_thunk(const void *data, OPENSSL_LH_HASHFUNC hfn) { unsigned long (*hfn_conv)(const PROPERTY_STRING *) = (unsigned long (*)(const PROPERTY_STRING *))hfn; return hfn_conv((const PROPERTY_STRING *)data); } static int lh_PROPERTY_STRING_cfn_thunk(const void *da, const void *db, OPENSSL_LH_COMPFUNC cfn) { int (*cfn_conv)(const PROPERTY_STRING *, const PROPERTY_STRING *) = (int (*)(const PROPERTY_STRING *, const PROPERTY_STRING *))cfn; return cfn_conv((const PROPERTY_STRING *)da, (const PROPERTY_STRING *)db); } static  inline void lh_PROPERTY_STRING_free(struct lhash_st_PROPERTY_STRING *lh) { OPENSSL_LH_free((OPENSSL_LHASH *)lh); }
static  inline PROPERTY_STRING * lh_PROPERTY_STRING_insert(struct lhash_st_PROPERTY_STRING *lh, PROPERTY_STRING *d) { return (PROPERTY_STRING *)OPENSSL_LH_insert((OPENSSL_LHASH *)lh, d); }
static  inline PROPERTY_STRING * lh_PROPERTY_STRING_retrieve(struct lhash_st_PROPERTY_STRING *lh, const PROPERTY_STRING *d) { return (PROPERTY_STRING *)OPENSSL_LH_retrieve((OPENSSL_LHASH *)lh, d); } static  inline int lh_PROPERTY_STRING_error(struct lhash_st_PROPERTY_STRING *lh) { return OPENSSL_LH_error((OPENSSL_LHASH *)lh); }
static  inline void lh_PROPERTY_STRING_doall_thunk(void *node, OPENSSL_LH_DOALL_FUNC doall) { void (*doall_conv)(PROPERTY_STRING *) = (void (*)(PROPERTY_STRING *))doall; doall_conv((PROPERTY_STRING *)node); } static  inline void lh_PROPERTY_STRING_doall_arg_thunk(void *node, void *arg, OPENSSL_LH_DOALL_FUNCARG doall) { void (*doall_conv)(PROPERTY_STRING *, void *) = (void (*)(PROPERTY_STRING *, void *))doall; doall_conv((PROPERTY_STRING *)node, arg); } static  inline void lh_PROPERTY_STRING_doall(struct lhash_st_PROPERTY_STRING *lh, void (*doall)(PROPERTY_STRING *)) { OPENSSL_LH_doall((OPENSSL_LHASH *)lh, (OPENSSL_LH_DOALL_FUNC)doall); } static  inline struct lhash_st_PROPERTY_STRING * lh_PROPERTY_STRING_new(unsigned long (*hfn)(const PROPERTY_STRING *), int (*cfn)(const PROPERTY_STRING *, const PROPERTY_STRING *)) { return (struct lhash_st_PROPERTY_STRING *)OPENSSL_LH_set_thunks(OPENSSL_LH_new((OPENSSL_LH_HASHFUNC)hfn, (OPENSSL_LH_COMPFUNC)cfn), lh_PROPERTY_STRING_hfn_thunk, lh_PROPERTY_STRING_cfn_thunk, lh_PROPERTY_STRING_doall_thunk, lh_PROPERTY_STRING_doall_arg_thunk); }
struct lhash_st_PROPERTY_STRING;
typedef struct lhash_st_PROPERTY_STRING PROP_TABLE;

typedef struct {
CRYPTO_RWLOCK *lock;
PROP_TABLE *prop_names;
PROP_TABLE *prop_values;
OSSL_PROPERTY_IDX prop_name_idx;
OSSL_PROPERTY_IDX prop_value_idx;

struct stack_st_OPENSSL_CSTRING *prop_namelist;
struct stack_st_OPENSSL_CSTRING *prop_valuelist;

} PROPERTY_STRING_DATA;

static unsigned long property_hash(const PROPERTY_STRING *a)
{
return OPENSSL_LH_strhash(a->s);
}

static int property_cmp(const PROPERTY_STRING *a, const PROPERTY_STRING *b)
{
return strcmp(a->s, b->s);
}

static void property_free(PROPERTY_STRING *ps)
{
CRYPTO_free(ps, "../crypto/property/property_string.c", 62);
}

static void property_table_free(PROP_TABLE **pt)
{
PROP_TABLE *t = *pt;

if (t != ((void*)0)) {
lh_PROPERTY_STRING_doall(t, &property_free);
lh_PROPERTY_STRING_free(t);
*pt = ((void*)0);
}
}

void ossl_property_string_data_free(void *vpropdata)
{
PROPERTY_STRING_DATA *propdata = vpropdata;

if (propdata == ((void*)0))
return;

CRYPTO_THREAD_lock_free(propdata->lock);
property_table_free(&propdata->prop_names);
property_table_free(&propdata->prop_values);

OPENSSL_sk_free(ossl_check_OPENSSL_CSTRING_sk_type(propdata->prop_namelist));
OPENSSL_sk_free(ossl_check_OPENSSL_CSTRING_sk_type(propdata->prop_valuelist));
propdata->prop_namelist = propdata->prop_valuelist = ((void*)0);

propdata->prop_name_idx = propdata->prop_value_idx = 0;

CRYPTO_free(propdata, "../crypto/property/property_string.c", 93);
}

void *ossl_property_string_data_new(OSSL_LIB_CTX *ctx) {
PROPERTY_STRING_DATA *propdata = CRYPTO_zalloc(sizeof(*propdata), "../crypto/property/property_string.c", 97);

if (propdata == ((void*)0))
return ((void*)0);

propdata->lock = CRYPTO_THREAD_lock_new();
propdata->prop_names = lh_PROPERTY_STRING_new(&property_hash,
&property_cmp);
propdata->prop_values = lh_PROPERTY_STRING_new(&property_hash,
&property_cmp);

propdata->prop_namelist = ((struct stack_st_OPENSSL_CSTRING *)OPENSSL_sk_new_null());
propdata->prop_valuelist = ((struct stack_st_OPENSSL_CSTRING *)OPENSSL_sk_new_null());

if (propdata->lock == ((void*)0)

|| propdata->prop_namelist == ((void*)0)
|| propdata->prop_valuelist == ((void*)0)

|| propdata->prop_names == ((void*)0)
|| propdata->prop_values == ((void*)0)) {
ossl_property_string_data_free(propdata);
return ((void*)0);
}
return propdata;
}

static PROPERTY_STRING *new_property_string(const char *s,
OSSL_PROPERTY_IDX *pidx)
{
const size_t l = strlen(s);
PROPERTY_STRING *ps = CRYPTO_malloc(sizeof(*ps) + l, "../crypto/property/property_string.c", 128);

if (ps != ((void*)0)) {
memcpy(ps->body, s, l + 1);
ps->s = ps->body;
ps->idx = ++*pidx;
if (ps->idx == 0) {
CRYPTO_free(ps, "../crypto/property/property_string.c", 135);
return ((void*)0);
}
}
return ps;
}

static OSSL_PROPERTY_IDX ossl_property_string(OSSL_LIB_CTX *ctx, int name,
int create, const char *s)
{
PROPERTY_STRING p, *ps, *ps_new;
PROP_TABLE *t;
OSSL_PROPERTY_IDX *pidx;
PROPERTY_STRING_DATA *propdata
= ossl_lib_ctx_get_data(ctx, 3);

if (propdata == ((void*)0))
return 0;

t = name ? propdata->prop_names : propdata->prop_values;
p.s = s;
if (!CRYPTO_THREAD_read_lock(propdata->lock)) {
(ERR_new(), ERR_set_debug("../crypto/property/property_string.c",157,__func__), ERR_set_error)((15),((271|((0x1 << 18L)|(0x2 << 18L)))),((void*)0));
return 0;
}
ps = lh_PROPERTY_STRING_retrieve(t, &p);
if (ps == ((void*)0) && create) {
CRYPTO_THREAD_unlock(propdata->lock);
if (!CRYPTO_THREAD_write_lock(propdata->lock)) {
(ERR_new(), ERR_set_debug("../crypto/property/property_string.c",164,__func__), ERR_set_error)((15),((272|((0x1 << 18L)|(0x2 << 18L)))),((void*)0));
return 0;
}
pidx = name ? &propdata->prop_name_idx : &propdata->prop_value_idx;
ps = lh_PROPERTY_STRING_retrieve(t, &p);
if (ps == ((void*)0) && (ps_new = new_property_string(s, pidx)) != ((void*)0)) {

struct stack_st_OPENSSL_CSTRING *slist;

slist = name ? propdata->prop_namelist : propdata->prop_valuelist;
if (OPENSSL_sk_push(ossl_check_OPENSSL_CSTRING_sk_type(slist), ossl_check_OPENSSL_CSTRING_type(ps_new->s)) <= 0) {
property_free(ps_new);
CRYPTO_THREAD_unlock(propdata->lock);
return 0;
}

lh_PROPERTY_STRING_insert(t, ps_new);
if (lh_PROPERTY_STRING_error(t)) {





((const char *)OPENSSL_sk_pop(ossl_check_OPENSSL_CSTRING_sk_type(slist)));

property_free(ps_new);
--*pidx;
CRYPTO_THREAD_unlock(propdata->lock);
return 0;
}
ps = ps_new;
}
}
CRYPTO_THREAD_unlock(propdata->lock);
return ps != ((void*)0) ? ps->idx : 0;
}
// 216 "../crypto/property/property_string.c"
OSSL_PROPERTY_IDX ossl_property_name(OSSL_LIB_CTX *ctx, const char *s,
int create)
{
return ossl_property_string(ctx, 1, create, s);
}

OSSL_PROPERTY_IDX ossl_property_value(OSSL_LIB_CTX *ctx, const char *s,
int create)
{
return ossl_property_string(ctx, 0, create, s);
}
