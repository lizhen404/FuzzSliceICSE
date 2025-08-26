#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/ex_data.c"
// 1 "../crypto/ex_data.c" 2
// 10 "../crypto/ex_data.c"
#include <stdlib.h>
// 11 "../crypto/ex_data.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/cryptlib.h"
// 12 "../crypto/ex_data.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/thread_once.h"
// 13 "../crypto/ex_data.c" 2

int ossl_do_ex_data_init(OSSL_LIB_CTX *ctx)
{
OSSL_EX_DATA_GLOBAL *global = ossl_lib_ctx_get_ex_data_global(ctx);

if (global == ((void*)0))
return 0;

global->ex_data_lock = CRYPTO_THREAD_lock_new();
return global->ex_data_lock != ((void*)0);
}







static void cleanup_cb(EX_CALLBACK *funcs)
{
CRYPTO_free(funcs, "../crypto/ex_data.c", 63);
}







void ossl_crypto_cleanup_all_ex_data_int(OSSL_LIB_CTX *ctx)
{
int i;
OSSL_EX_DATA_GLOBAL *global = ossl_lib_ctx_get_ex_data_global(ctx);

if (global == ((void*)0))
return;

for (i = 0; i < 18; ++i) {
EX_CALLBACKS *ip = &global->ex_data[i];

sk_EX_CALLBACK_pop_free(ip->meth, cleanup_cb);
ip->meth = ((void*)0);
}

CRYPTO_THREAD_lock_free(global->ex_data_lock);
global->ex_data_lock = ((void*)0);
}






// 219 "../crypto/ex_data.c"
struct ex_callback_entry {
const EX_CALLBACK *excb;
int index;
};
