#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/bio/bss_core.c"
// 1 "../crypto/bio/bss_core.c" 2
// 10 "../crypto/bio/bss_core.c"
#include "/StaticSlicer/test_lib/openssl/include/openssl/core_dispatch.h"
// 11 "../crypto/bio/bss_core.c" 2
#include "/StaticSlicer/test_lib/openssl/crypto/bio/bio_local.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"
// 12 "../crypto/bio/bss_core.c" 2

#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 14 "../crypto/bio/bss_core.c" 2

typedef struct {
OSSL_FUNC_BIO_read_ex_fn *c_bio_read_ex;
OSSL_FUNC_BIO_write_ex_fn *c_bio_write_ex;
OSSL_FUNC_BIO_gets_fn *c_bio_gets;
OSSL_FUNC_BIO_puts_fn *c_bio_puts;
OSSL_FUNC_BIO_ctrl_fn *c_bio_ctrl;
OSSL_FUNC_BIO_up_ref_fn *c_bio_up_ref;
OSSL_FUNC_BIO_free_fn *c_bio_free;
} BIO_CORE_GLOBALS;

void ossl_bio_core_globals_free(void *vbcg)
{
CRYPTO_free(vbcg, "../crypto/bio/bss_core.c", 27);
}

void *ossl_bio_core_globals_new(OSSL_LIB_CTX *ctx)
{
return CRYPTO_zalloc(sizeof(BIO_CORE_GLOBALS), "../crypto/bio/bss_core.c", 32);
}


