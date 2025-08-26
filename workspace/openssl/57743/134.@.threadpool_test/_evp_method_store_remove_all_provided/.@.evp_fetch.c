#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/evp/evp_fetch.c"
// 1 "../crypto/evp/evp_fetch.c" 2
// 10 "../crypto/evp/evp_fetch.c"
// 11 "../crypto/evp/evp_fetch.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/types.h"
// 12 "../crypto/evp/evp_fetch.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/evp.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/core.h"
// 13 "../crypto/evp/evp_fetch.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"
// 15 "../crypto/evp/evp_fetch.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/thread_once.h"
// 16 "../crypto/evp/evp_fetch.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/property.h"
// 17 "../crypto/evp/evp_fetch.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/core.h"
// 18 "../crypto/evp/evp_fetch.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/provider.h"
// 19 "../crypto/evp/evp_fetch.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/namemap.h"
// 20 "../crypto/evp/evp_fetch.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/decoder.h"
// 21 "../crypto/evp/evp_fetch.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/evp.h"
// 22 "../crypto/evp/evp_fetch.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/evp/evp_local.h"
// 23 "../crypto/evp/evp_fetch.c" 2




struct evp_method_data_st {
OSSL_LIB_CTX *libctx;
int operation_id;
int name_id;
const char *names;
const char *propquery;

OSSL_METHOD_STORE *tmp_store;

unsigned int flag_construct_error_occurred : 1;

void *(*method_from_algorithm)(int name_id, const OSSL_ALGORITHM *,
OSSL_PROVIDER *);
int (*refcnt_up_method)(void *method);
void (*destruct_method)(void *method);
};




static OSSL_METHOD_STORE *get_evp_method_store(OSSL_LIB_CTX *libctx)
{
return ossl_lib_ctx_get_data(libctx, 0);
}

// 111 "../crypto/evp/evp_fetch.c"
int evp_method_store_remove_all_provided(const OSSL_PROVIDER *prov)
{
OSSL_LIB_CTX *libctx = ossl_provider_libctx(prov);
OSSL_METHOD_STORE *store = get_evp_method_store(libctx);

if (store != ((void*)0))
return ossl_method_store_remove_all_provided(store, prov);
return 1;
}

struct filter_data_st {
int operation_id;
void (*user_fn)(void *method, void *arg);
void *user_arg;
};
