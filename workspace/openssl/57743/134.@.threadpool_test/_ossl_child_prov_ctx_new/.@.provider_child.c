#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/provider_child.c"
// 1 "../crypto/provider_child.c" 2
// 10 "../crypto/provider_child.c"
#include <assert.h>
// 11 "../crypto/provider_child.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/crypto.h"
// 12 "../crypto/provider_child.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/core_dispatch.h"
// 13 "../crypto/provider_child.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/core_names.h"
// 14 "../crypto/provider_child.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/provider.h"
// 15 "../crypto/provider_child.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/evp.h"
// 16 "../crypto/provider_child.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/provider.h"
// 17 "../crypto/provider_child.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"
// 18 "../crypto/provider_child.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/evp.h"
// 19 "../crypto/provider_child.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 20 "../crypto/provider_child.c" 2

struct stack_st_OSSL_PROVIDER; typedef int (*sk_OSSL_PROVIDER_compfunc)(const OSSL_PROVIDER * const *a, const OSSL_PROVIDER *const *b); typedef void (*sk_OSSL_PROVIDER_freefunc)(OSSL_PROVIDER *a); typedef OSSL_PROVIDER * (*sk_OSSL_PROVIDER_copyfunc)(const OSSL_PROVIDER *a);
struct child_prov_globals {
const OSSL_CORE_HANDLE *handle;
const OSSL_CORE_HANDLE *curr_prov;
CRYPTO_RWLOCK *lock;
OSSL_FUNC_core_get_libctx_fn *c_get_libctx;
OSSL_FUNC_provider_register_child_cb_fn *c_provider_register_child_cb;
OSSL_FUNC_provider_deregister_child_cb_fn *c_provider_deregister_child_cb;
OSSL_FUNC_provider_name_fn *c_prov_name;
OSSL_FUNC_provider_get0_provider_ctx_fn *c_prov_get0_provider_ctx;
OSSL_FUNC_provider_get0_dispatch_fn *c_prov_get0_dispatch;
OSSL_FUNC_provider_up_ref_fn *c_prov_up_ref;
OSSL_FUNC_provider_free_fn *c_prov_free;
};

void *ossl_child_prov_ctx_new(OSSL_LIB_CTX *libctx)
{
return CRYPTO_zalloc(sizeof(struct child_prov_globals), "../crypto/provider_child.c", 39);
}

void ossl_child_prov_ctx_free(void *vgbl)
{
struct child_prov_globals *gbl = vgbl;

CRYPTO_THREAD_lock_free(gbl->lock);
CRYPTO_free(gbl, "../crypto/provider_child.c", 47);
}



// 286 "../crypto/provider_child.c"
int ossl_provider_free_parent(OSSL_PROVIDER *prov, int deactivate)
{
struct child_prov_globals *gbl;
const OSSL_CORE_HANDLE *parent_handle;

gbl = ossl_lib_ctx_get_data(ossl_provider_libctx(prov),
18);
if (gbl == ((void*)0))
return 0;

parent_handle = ossl_provider_get_parent(prov);
if (parent_handle == gbl->handle)
return 1;
return gbl->c_prov_free(ossl_provider_get_parent(prov), deactivate);
}