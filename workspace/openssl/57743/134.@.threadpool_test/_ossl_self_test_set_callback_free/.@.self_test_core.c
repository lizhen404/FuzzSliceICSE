#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/self_test_core.c"
// 1 "../crypto/self_test_core.c" 2
// 10 "../crypto/self_test_core.c"
#include "/StaticSlicer/test_lib/openssl/include/openssl/self_test.h"
// 11 "../crypto/self_test_core.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/core_names.h"
// 12 "../crypto/self_test_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/params.h"
// 13 "../crypto/self_test_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"
// 14 "../crypto/self_test_core.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 15 "../crypto/self_test_core.c" 2

typedef struct self_test_cb_st
{
OSSL_CALLBACK *cb;
void *cbarg;
} SELF_TEST_CB;

struct ossl_self_test_st
{

const char *phase;
const char *type;
const char *desc;
OSSL_CALLBACK *cb;


OSSL_PARAM params[4];
void *cb_arg;
};


void *ossl_self_test_set_callback_new(OSSL_LIB_CTX *ctx)
{
SELF_TEST_CB *stcb;

stcb = CRYPTO_zalloc(sizeof(*stcb), "../crypto/self_test_core.c", 40);
return stcb;
}

void ossl_self_test_set_callback_free(void *stcb)
{
CRYPTO_free(stcb, "../crypto/self_test_core.c", 46);
}

// 155 "../crypto/self_test_core.c"