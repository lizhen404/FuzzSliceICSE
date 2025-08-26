#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/context.c"
// 1 "../crypto/context.c" 2
// 10 "../crypto/context.c"
#include "/StaticSlicer/test_lib/openssl/include/crypto/cryptlib.h"
// 11 "../crypto/context.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/conf.h"
// 12 "../crypto/context.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/thread_once.h"
// 13 "../crypto/context.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/property.h"
// 14 "../crypto/context.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/core.h"
// 15 "../crypto/context.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/bio.h"
// 16 "../crypto/context.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/provider.h"
// 17 "../crypto/context.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/decoder.h"
// 18 "../crypto/context.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/context.h"
// 19 "../crypto/context.c" 2

struct ossl_lib_ctx_st {
CRYPTO_RWLOCK *lock, *rand_crngt_lock;
OSSL_EX_DATA_GLOBAL global;

void *property_string_data;
void *evp_method_store;
void *provider_store;
void *namemap;
void *property_defns;
void *global_properties;
void *drbg;
void *drbg_nonce;

void *provider_conf;
void *bio_core;
void *child_provider;
OSSL_METHOD_STORE *decoder_store;
void *decoder_cache;
OSSL_METHOD_STORE *encoder_store;
OSSL_METHOD_STORE *store_loader_store;
void *self_test_cb;


void *threads;

void *rand_crngt;





unsigned int ischild:1;
};

static void context_deinit_objs(OSSL_LIB_CTX *ctx);

static int context_init(OSSL_LIB_CTX *ctx)
{
int exdata_done = 0;

ctx->lock = CRYPTO_THREAD_lock_new();
if (ctx->lock == ((void*)0))
return 0;

ctx->rand_crngt_lock = CRYPTO_THREAD_lock_new();
if (ctx->rand_crngt_lock == ((void*)0))
goto err;


if (!ossl_do_ex_data_init(ctx))
goto err;
exdata_done = 1;


ctx->evp_method_store = ossl_method_store_new(ctx);
if (ctx->evp_method_store == ((void*)0))
goto err;



ctx->provider_conf = ossl_prov_conf_ctx_new(ctx);
if (ctx->provider_conf == ((void*)0))
goto err;



ctx->drbg = ossl_rand_ctx_new(ctx);
if (ctx->drbg == ((void*)0))
goto err;






ctx->decoder_store = ossl_method_store_new(ctx);
if (ctx->decoder_store == ((void*)0))
goto err;
ctx->decoder_cache = ossl_decoder_cache_new(ctx);
if (ctx->decoder_cache == ((void*)0))
goto err;


ctx->encoder_store = ossl_method_store_new(ctx);
if (ctx->encoder_store == ((void*)0))
goto err;


ctx->store_loader_store = ossl_method_store_new(ctx);
if (ctx->store_loader_store == ((void*)0))
goto err;



ctx->provider_store = ossl_provider_store_new(ctx);
if (ctx->provider_store == ((void*)0))
goto err;


ctx->property_string_data = ossl_property_string_data_new(ctx);
if (ctx->property_string_data == ((void*)0))
goto err;

ctx->namemap = ossl_stored_namemap_new(ctx);
if (ctx->namemap == ((void*)0))
goto err;

ctx->property_defns = ossl_property_defns_new(ctx);
if (ctx->property_defns == ((void*)0))
goto err;

ctx->global_properties = ossl_ctx_global_properties_new(ctx);
if (ctx->global_properties == ((void*)0))
goto err;


ctx->bio_core = ossl_bio_core_globals_new(ctx);
if (ctx->bio_core == ((void*)0))
goto err;


ctx->drbg_nonce = ossl_prov_drbg_nonce_ctx_new(ctx);
if (ctx->drbg_nonce == ((void*)0))
goto err;


ctx->self_test_cb = ossl_self_test_set_callback_new(ctx);
if (ctx->self_test_cb == ((void*)0))
goto err;
// 186 "../crypto/context.c"
ctx->threads = ossl_threads_ctx_new(ctx);
if (ctx->threads == ((void*)0))
goto err;




ctx->child_provider = ossl_child_prov_ctx_new(ctx);
if (ctx->child_provider == ((void*)0))
goto err;



if (!ossl_property_parse_init(ctx))
goto err;

return 1;

err:
context_deinit_objs(ctx);

if (exdata_done)
ossl_crypto_cleanup_all_ex_data_int(ctx);

CRYPTO_THREAD_lock_free(ctx->rand_crngt_lock);
CRYPTO_THREAD_lock_free(ctx->lock);
memset(ctx, '\0', sizeof(*ctx));
return 0;
}

static void context_deinit_objs(OSSL_LIB_CTX *ctx)
{

if (ctx->evp_method_store != ((void*)0)) {
ossl_method_store_free(ctx->evp_method_store);
ctx->evp_method_store = ((void*)0);
}


if (ctx->drbg != ((void*)0)) {
ossl_rand_ctx_free(ctx->drbg);
ctx->drbg = ((void*)0);
}



if (ctx->provider_conf != ((void*)0)) {
ossl_prov_conf_ctx_free(ctx->provider_conf);
ctx->provider_conf = ((void*)0);
}





if (ctx->decoder_store != ((void*)0)) {
ossl_method_store_free(ctx->decoder_store);
ctx->decoder_store = ((void*)0);
}
if (ctx->decoder_cache != ((void*)0)) {
ossl_decoder_cache_free(ctx->decoder_cache);
ctx->decoder_cache = ((void*)0);
}



if (ctx->encoder_store != ((void*)0)) {
ossl_method_store_free(ctx->encoder_store);
ctx->encoder_store = ((void*)0);
}


if (ctx->store_loader_store != ((void*)0)) {
ossl_method_store_free(ctx->store_loader_store);
ctx->store_loader_store = ((void*)0);
}



if (ctx->provider_store != ((void*)0)) {
ossl_provider_store_free(ctx->provider_store);
ctx->provider_store = ((void*)0);
}


if (ctx->property_string_data != ((void*)0)) {
ossl_property_string_data_free(ctx->property_string_data);
ctx->property_string_data = ((void*)0);
}

if (ctx->namemap != ((void*)0)) {
ossl_stored_namemap_free(ctx->namemap);
ctx->namemap = ((void*)0);
}

if (ctx->property_defns != ((void*)0)) {
ossl_property_defns_free(ctx->property_defns);
ctx->property_defns = ((void*)0);
}

if (ctx->global_properties != ((void*)0)) {
ossl_ctx_global_properties_free(ctx->global_properties);
ctx->global_properties = ((void*)0);
}


if (ctx->bio_core != ((void*)0)) {
ossl_bio_core_globals_free(ctx->bio_core);
ctx->bio_core = ((void*)0);
}


if (ctx->drbg_nonce != ((void*)0)) {
ossl_prov_drbg_nonce_ctx_free(ctx->drbg_nonce);
ctx->drbg_nonce = ((void*)0);
}


if (ctx->self_test_cb != ((void*)0)) {
ossl_self_test_set_callback_free(ctx->self_test_cb);
ctx->self_test_cb = ((void*)0);
}


if (ctx->rand_crngt != ((void*)0)) {
ossl_rand_crng_ctx_free(ctx->rand_crngt);
ctx->rand_crngt = ((void*)0);
}
// 328 "../crypto/context.c"
if (ctx->threads != ((void*)0)) {
ossl_threads_ctx_free(ctx->threads);
ctx->threads = ((void*)0);
}




if (ctx->child_provider != ((void*)0)) {
ossl_child_prov_ctx_free(ctx->child_provider);
ctx->child_provider = ((void*)0);
}

}

static OSSL_LIB_CTX default_context_int;

static CRYPTO_ONCE default_context_init = 0;
static CRYPTO_THREAD_LOCAL default_context_thread_local;
static int default_context_inited = 0;

static int default_context_do_init(void); static int default_context_do_init_ossl_ret_ = 0; static void default_context_do_init_ossl_(void) { default_context_do_init_ossl_ret_ = default_context_do_init(); } static int default_context_do_init(void)
{
if (!CRYPTO_THREAD_init_local(&default_context_thread_local, ((void*)0)))
goto err;

if (!context_init(&default_context_int))
goto deinit_thread;

default_context_inited = 1;
return 1;

deinit_thread:
CRYPTO_THREAD_cleanup_local(&default_context_thread_local);
err:
return 0;
}

static OSSL_LIB_CTX *get_thread_default_context(void)
{
if (!(CRYPTO_THREAD_run_once(&default_context_init, default_context_do_init_ossl_) ? default_context_do_init_ossl_ret_ : 0))
return ((void*)0);

return CRYPTO_THREAD_get_local(&default_context_thread_local);
}

static OSSL_LIB_CTX *get_default_context(void)
{
OSSL_LIB_CTX *current_defctx = get_thread_default_context();

if (current_defctx == ((void*)0))
current_defctx = &default_context_int;
return current_defctx;
}

OSSL_LIB_CTX *ossl_lib_ctx_get_concrete(OSSL_LIB_CTX *ctx)
{

if (ctx == ((void*)0))
return get_default_context();

return ctx;
}

void *ossl_lib_ctx_get_data(OSSL_LIB_CTX *ctx, int index)
{
void *p;

ctx = ossl_lib_ctx_get_concrete(ctx);
if (ctx == ((void*)0))
return ((void*)0);

switch (index) {
case 3:
return ctx->property_string_data;
case 0:
return ctx->evp_method_store;
case 1:
return ctx->provider_store;
case 4:
return ctx->namemap;
case 2:
return ctx->property_defns;
case 14:
return ctx->global_properties;
case 5:
return ctx->drbg;
case 6:
return ctx->drbg_nonce;

case 16:
return ctx->provider_conf;
case 17:
return ctx->bio_core;
case 18:
return ctx->child_provider;
case 11:
return ctx->decoder_store;
case 20:
return ctx->decoder_cache;
case 10:
return ctx->encoder_store;
case 15:
return ctx->store_loader_store;
case 12:
return ctx->self_test_cb;


case 19:
return ctx->threads;


case 7: {
// 602 "../crypto/context.c"
if (CRYPTO_THREAD_read_lock(ctx->rand_crngt_lock) != 1)
return ((void*)0);

if (ctx->rand_crngt == ((void*)0)) {
CRYPTO_THREAD_unlock(ctx->rand_crngt_lock);

if (CRYPTO_THREAD_write_lock(ctx->rand_crngt_lock) != 1)
return ((void*)0);

if (ctx->rand_crngt == ((void*)0))
ctx->rand_crngt = ossl_rand_crng_ctx_new(ctx);
}

p = ctx->rand_crngt;

CRYPTO_THREAD_unlock(ctx->rand_crngt_lock);

return p;
}
// 630 "../crypto/context.c"
default:
return ((void*)0);
}
}

OSSL_EX_DATA_GLOBAL *ossl_lib_ctx_get_ex_data_global(OSSL_LIB_CTX *ctx)
{
ctx = ossl_lib_ctx_get_concrete(ctx);
if (ctx == ((void*)0))
return ((void*)0);
return &ctx->global;
}
