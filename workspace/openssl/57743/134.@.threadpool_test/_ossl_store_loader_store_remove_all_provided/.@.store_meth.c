#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/store/store_meth.c"
// 1 "../crypto/store/store_meth.c" 2
// 10 "../crypto/store/store_meth.c"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/crypto.h"
// 11 "../crypto/store/store_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/store.h"
// 12 "../crypto/store/store_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/core.h"
// 13 "../crypto/store/store_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/namemap.h"
// 14 "../crypto/store/store_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/property.h"
// 15 "../crypto/store/store_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/provider.h"
// 16 "../crypto/store/store_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/store/store_local.h"
// 17 "../crypto/store/store_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 18 "../crypto/store/store_meth.c" 2

struct loader_data_st {
OSSL_LIB_CTX *libctx;
int scheme_id;
const char *scheme;
const char *propquery;

OSSL_METHOD_STORE *tmp_store;

unsigned int flag_construct_error_occurred : 1;
};







static OSSL_METHOD_STORE *get_loader_store(OSSL_LIB_CTX *libctx)
{
return ossl_lib_ctx_get_data(libctx, 15);
}

int ossl_store_loader_store_remove_all_provided(const OSSL_PROVIDER *prov)
{
OSSL_LIB_CTX *libctx = ossl_provider_libctx(prov);
OSSL_METHOD_STORE *store = get_loader_store(libctx);

if (store != ((void*)0))
return ossl_method_store_remove_all_provided(store, prov);
return 1;
}





struct do_one_data_st {
void (*user_fn)(OSSL_STORE_LOADER *loader, void *arg);
void *user_arg;
};
