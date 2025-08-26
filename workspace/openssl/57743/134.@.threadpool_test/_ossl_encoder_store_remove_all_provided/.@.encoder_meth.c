#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/encode_decode/encoder_meth.c"
// 1 "../crypto/encode_decode/encoder_meth.c" 2
// 10 "../crypto/encode_decode/encoder_meth.c"
#include "/StaticSlicer/test_lib/openssl/include/openssl/core.h"
// 11 "../crypto/encode_decode/encoder_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/core_dispatch.h"
// 12 "../crypto/encode_decode/encoder_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/encoder.h"
// 13 "../crypto/encode_decode/encoder_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/ui.h"
// 14 "../crypto/encode_decode/encoder_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/core.h"
// 15 "../crypto/encode_decode/encoder_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/namemap.h"
// 16 "../crypto/encode_decode/encoder_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/property.h"
// 17 "../crypto/encode_decode/encoder_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/provider.h"
// 18 "../crypto/encode_decode/encoder_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/encoder.h"
// 19 "../crypto/encode_decode/encoder_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/encode_decode/encoder_local.h"
// 20 "../crypto/encode_decode/encoder_meth.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 21 "../crypto/encode_decode/encoder_meth.c" 2







struct encoder_data_st {
OSSL_LIB_CTX *libctx;
int id;
const char *names;
const char *propquery;

OSSL_METHOD_STORE *tmp_store;

unsigned int flag_construct_error_occurred : 1;
};







static OSSL_METHOD_STORE *get_encoder_store(OSSL_LIB_CTX *libctx)
{
return ossl_lib_ctx_get_data(libctx, 10);
}

int ossl_encoder_store_remove_all_provided(const OSSL_PROVIDER *prov)
{
OSSL_LIB_CTX *libctx = ossl_provider_libctx(prov);
OSSL_METHOD_STORE *store = get_encoder_store(libctx);

if (store != ((void*)0))
return ossl_method_store_remove_all_provided(store, prov);
return 1;
}





struct do_one_data_st {
void (*user_fn)(OSSL_ENCODER *encoder, void *arg);
void *user_arg;
};
