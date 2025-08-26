#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../test/tls-provider.c"

// 1 "../test/tls-provider.c" 2

// 10 "../test/tls-provider.c"


// 11 "../test/tls-provider.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/core_names.h"

// 12 "../test/tls-provider.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/core_dispatch.h"

// 13 "../test/tls-provider.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/rand.h"

#include "/StaticSlicer/test_lib/openssl/include/openssl/params.h"

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/asn1.h"

// 14 "../test/tls-provider.c" 2



#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/err.h"

// 16 "../test/tls-provider.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/proverr.h"

// 17 "../test/tls-provider.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/pkcs12.h"

// 18 "../test/tls-provider.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/provider.h"

// 19 "../test/tls-provider.c" 2

#include <assert.h>

// 20 "../test/tls-provider.c" 2



#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/asn1t.h"

// 22 "../test/tls-provider.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/core_object.h"

// 23 "../test/tls-provider.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/asn1.h"

// 24 "../test/tls-provider.c" 2



#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/ssl.h"

// 26 "../test/tls-provider.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/nelem.h"

// 27 "../test/tls-provider.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/refcount.h"

// 28 "../test/tls-provider.c" 2

// 48 "../test/tls-provider.c"

static OSSL_FUNC_keymgmt_import_fn xor_import;

static OSSL_FUNC_keymgmt_import_types_fn xor_import_types;

static OSSL_FUNC_keymgmt_import_types_ex_fn xor_import_types_ex;

static OSSL_FUNC_keymgmt_export_fn xor_export;

static OSSL_FUNC_keymgmt_export_types_fn xor_export_types;

static OSSL_FUNC_keymgmt_export_types_ex_fn xor_export_types_ex;



int tls_provider_init(const OSSL_CORE_HANDLE *handle,

const OSSL_DISPATCH *in,

const OSSL_DISPATCH **out,

void **provctx);

// 68 "../test/tls-provider.c"

static const unsigned char private_constant[32] = {

0xd3, 0x6b, 0x54, 0xec, 0x5b, 0xac, 0x89, 0x96, 0x8c, 0x2c, 0x66, 0xa5,

0x67, 0x0d, 0xe3, 0xdd, 0x43, 0x69, 0xbc, 0x83, 0x3d, 0x60, 0xc7, 0xb8,

0x2b, 0x1c, 0x5a, 0xfd, 0xb5, 0xcd, 0xd0, 0xf8

};



typedef struct xorkey_st {

unsigned char privkey[32];

unsigned char pubkey[32];

int hasprivkey;

int haspubkey;

char *tls_name;

CRYPTO_REF_COUNT references;

} XORKEY;







static OSSL_FUNC_keymgmt_new_fn xor_newkey;

static OSSL_FUNC_keymgmt_free_fn xor_freekey;

static OSSL_FUNC_keymgmt_has_fn xor_has;

static OSSL_FUNC_keymgmt_dup_fn xor_dup;

static OSSL_FUNC_keymgmt_gen_init_fn xor_gen_init;

static OSSL_FUNC_keymgmt_gen_set_params_fn xor_gen_set_params;

static OSSL_FUNC_keymgmt_gen_settable_params_fn xor_gen_settable_params;

static OSSL_FUNC_keymgmt_gen_fn xor_gen;

static OSSL_FUNC_keymgmt_gen_cleanup_fn xor_gen_cleanup;

static OSSL_FUNC_keymgmt_load_fn xor_load;

static OSSL_FUNC_keymgmt_get_params_fn xor_get_params;

static OSSL_FUNC_keymgmt_gettable_params_fn xor_gettable_params;

static OSSL_FUNC_keymgmt_set_params_fn xor_set_params;

static OSSL_FUNC_keymgmt_settable_params_fn xor_settable_params;













static OSSL_FUNC_keyexch_newctx_fn xor_newkemkexctx;

static OSSL_FUNC_keyexch_init_fn xor_init;

static OSSL_FUNC_keyexch_set_peer_fn xor_set_peer;

static OSSL_FUNC_keyexch_derive_fn xor_derive;

static OSSL_FUNC_keyexch_freectx_fn xor_freectx;

static OSSL_FUNC_keyexch_dupctx_fn xor_dupctx;













static OSSL_FUNC_kem_newctx_fn xor_newkemkexctx;

static OSSL_FUNC_kem_freectx_fn xor_freectx;

static OSSL_FUNC_kem_dupctx_fn xor_dupctx;

static OSSL_FUNC_kem_encapsulate_init_fn xor_init;

static OSSL_FUNC_kem_encapsulate_fn xor_encapsulate;

static OSSL_FUNC_kem_decapsulate_init_fn xor_init;

static OSSL_FUNC_kem_decapsulate_fn xor_decapsulate;









static OSSL_FUNC_keymgmt_new_fn *

xor_prov_get_keymgmt_new(const OSSL_DISPATCH *fns)

{



for (; fns->function_id != 0; fns++)

if (fns->function_id == 1)

return OSSL_FUNC_keymgmt_new(fns);



return ((void*)0);

}



static OSSL_FUNC_keymgmt_free_fn *

xor_prov_get_keymgmt_free(const OSSL_DISPATCH *fns)

{



for (; fns->function_id != 0; fns++)

if (fns->function_id == 10)

return OSSL_FUNC_keymgmt_free(fns);



return ((void*)0);

}



static OSSL_FUNC_keymgmt_import_fn *

xor_prov_get_keymgmt_import(const OSSL_DISPATCH *fns)

{



for (; fns->function_id != 0; fns++)

if (fns->function_id == 40)

return OSSL_FUNC_keymgmt_import(fns);



return ((void*)0);

}



static OSSL_FUNC_keymgmt_export_fn *

xor_prov_get_keymgmt_export(const OSSL_DISPATCH *fns)

{



for (; fns->function_id != 0; fns++)

if (fns->function_id == 42)

return OSSL_FUNC_keymgmt_export(fns);



return ((void*)0);

}



static void *xor_prov_import_key(const OSSL_DISPATCH *fns, void *provctx,

int selection, const OSSL_PARAM params[])

{

OSSL_FUNC_keymgmt_new_fn *kmgmt_new = xor_prov_get_keymgmt_new(fns);

OSSL_FUNC_keymgmt_free_fn *kmgmt_free = xor_prov_get_keymgmt_free(fns);

OSSL_FUNC_keymgmt_import_fn *kmgmt_import =

xor_prov_get_keymgmt_import(fns);

void *key = ((void*)0);



if (kmgmt_new != ((void*)0) && kmgmt_import != ((void*)0) && kmgmt_free != ((void*)0)) {

if ((key = kmgmt_new(provctx)) == ((void*)0)

|| !kmgmt_import(key, selection, params)) {

kmgmt_free(key);

key = ((void*)0);

}

}

return key;

}



static void xor_prov_free_key(const OSSL_DISPATCH *fns, void *key)

{

OSSL_FUNC_keymgmt_free_fn *kmgmt_free = xor_prov_get_keymgmt_free(fns);



if (kmgmt_free != ((void*)0))

kmgmt_free(key);

}











struct tls_group_st {

unsigned int group_id;

unsigned int secbits;

unsigned int mintls;

unsigned int maxtls;

unsigned int mindtls;

unsigned int maxdtls;

unsigned int is_kem;

};







static struct tls_group_st xor_group = {

0,

128,

0x0304,

0,

-1,

-1,

0

};







static struct tls_group_st xor_kemgroup = {

0,

128,

0x0304,

0,

-1,

-1,

1

};







static const OSSL_PARAM xor_group_params[] = {

{ (("tls-group-name")), (4), (("xorgroup")), (sizeof("xorgroup")), ((size_t)-1) },



{ (("tls-group-name-internal")), (4), (("xorgroup-int")), (sizeof("xorgroup-int")), ((size_t)-1) },





{ (("tls-group-alg")), (4), (("XOR")), (sizeof("XOR")), ((size_t)-1) },



{ (("tls-group-id")), (2), ((&xor_group.group_id)), (sizeof(unsigned int)), ((size_t)-1) },

{ (("tls-group-sec-bits")), (2), ((&xor_group.secbits)), (sizeof(unsigned int)), ((size_t)-1) },



{ (("tls-min-tls")), (1), ((&xor_group.mintls)), (sizeof(int)), ((size_t)-1) },

{ (("tls-max-tls")), (1), ((&xor_group.maxtls)), (sizeof(int)), ((size_t)-1) },

{ (("tls-min-dtls")), (1), ((&xor_group.mindtls)), (sizeof(int)), ((size_t)-1) },

{ (("tls-max-dtls")), (1), ((&xor_group.maxdtls)), (sizeof(int)), ((size_t)-1) },

{ (("tls-group-is-kem")), (2), ((&xor_group.is_kem)), (sizeof(unsigned int)), ((size_t)-1) },

{ ((void*)0), 0, ((void*)0), 0, 0 }

};



static const OSSL_PARAM xor_kemgroup_params[] = {

{ (("tls-group-name")), (4), (("xorkemgroup")), (sizeof("xorkemgroup")), ((size_t)-1) },



{ (("tls-group-name-internal")), (4), (("xorkemgroup-int")), (sizeof("xorkemgroup-int")), ((size_t)-1) },





{ (("tls-group-alg")), (4), (("XOR")), (sizeof("XOR")), ((size_t)-1) },



{ (("tls-group-id")), (2), ((&xor_kemgroup.group_id)), (sizeof(unsigned int)), ((size_t)-1) },

{ (("tls-group-sec-bits")), (2), ((&xor_kemgroup.secbits)), (sizeof(unsigned int)), ((size_t)-1) },



{ (("tls-min-tls")), (1), ((&xor_kemgroup.mintls)), (sizeof(int)), ((size_t)-1) },

{ (("tls-max-tls")), (1), ((&xor_kemgroup.maxtls)), (sizeof(int)), ((size_t)-1) },

{ (("tls-min-dtls")), (1), ((&xor_kemgroup.mindtls)), (sizeof(int)), ((size_t)-1) },

{ (("tls-max-dtls")), (1), ((&xor_kemgroup.maxdtls)), (sizeof(int)), ((size_t)-1) },

{ (("tls-group-is-kem")), (2), ((&xor_kemgroup.is_kem)), (sizeof(unsigned int)), ((size_t)-1) },

{ ((void*)0), 0, ((void*)0), 0, 0 }

};





static char *dummy_group_names[50];









struct tls_sigalg_st {

unsigned int code_point;

unsigned int secbits;

unsigned int mintls;

unsigned int maxtls;

};

// 298 "../test/tls-provider.c"

static struct tls_sigalg_st xor_sigalg = {

0,

128,

0x0304,

0,

};



static struct tls_sigalg_st xor_sigalg_hash = {

0,

128,

0x0304,

0,

};



static struct tls_sigalg_st xor_sigalg12 = {

0,

128,

0x0303,

0x0303,

};



static const OSSL_PARAM xor_sig_nohash_params[] = {

{ (("tls-sigalg-iana-name")), (4), (("xorhmacsig")), (sizeof("xorhmacsig")), ((size_t)-1) },



{ (("tls-sigalg-name")), (4), (("xorhmacsig")), (sizeof("xorhmacsig")), ((size_t)-1) },





{ (("tls-sigalg-oid")), (4), (("1.3.6.1.4.1.16604.998888.1")), (sizeof("1.3.6.1.4.1.16604.998888.1")), ((size_t)-1) },



{ (("tls-sigalg-code-point")), (2), ((&xor_sigalg.code_point)), (sizeof(unsigned int)), ((size_t)-1) },



{ (("tls-sigalg-sec-bits")), (2), ((&xor_sigalg.secbits)), (sizeof(unsigned int)), ((size_t)-1) },



{ (("tls-min-tls")), (1), ((&xor_sigalg.mintls)), (sizeof(int)), ((size_t)-1) },



{ (("tls-max-tls")), (1), ((&xor_sigalg.maxtls)), (sizeof(int)), ((size_t)-1) },



{ ((void*)0), 0, ((void*)0), 0, 0 }

};



static const OSSL_PARAM xor_sig_hash_params[] = {

{ (("tls-sigalg-iana-name")), (4), (("xorhmacsha2sig")), (sizeof("xorhmacsha2sig")), ((size_t)-1) },



{ (("tls-sigalg-name")), (4), (("xorhmacsha2sig")), (sizeof("xorhmacsha2sig")), ((size_t)-1) },





{ (("tls-sigalg-hash-name")), (4), (("SHA256")), (sizeof("SHA256")), ((size_t)-1) },



{ (("tls-sigalg-oid")), (4), (("1.3.6.1.4.1.16604.998888.2")), (sizeof("1.3.6.1.4.1.16604.998888.2")), ((size_t)-1) },



{ (("tls-sigalg-code-point")), (2), ((&xor_sigalg_hash.code_point)), (sizeof(unsigned int)), ((size_t)-1) },



{ (("tls-sigalg-sec-bits")), (2), ((&xor_sigalg_hash.secbits)), (sizeof(unsigned int)), ((size_t)-1) },



{ (("tls-min-tls")), (1), ((&xor_sigalg_hash.mintls)), (sizeof(int)), ((size_t)-1) },



{ (("tls-max-tls")), (1), ((&xor_sigalg_hash.maxtls)), (sizeof(int)), ((size_t)-1) },



{ ((void*)0), 0, ((void*)0), 0, 0 }

};



static const OSSL_PARAM xor_sig_12_params[] = {

{ (("tls-sigalg-iana-name")), (4), (("xorhmacsig12")), (sizeof("xorhmacsig12")), ((size_t)-1) },



{ (("tls-sigalg-name")), (4), (("xorhmacsig12")), (sizeof("xorhmacsig12")), ((size_t)-1) },





{ (("tls-sigalg-oid")), (4), (("1.3.6.1.4.1.16604.998888.3")), (sizeof("1.3.6.1.4.1.16604.998888.3")), ((size_t)-1) },



{ (("tls-sigalg-code-point")), (2), ((&xor_sigalg12.code_point)), (sizeof(unsigned int)), ((size_t)-1) },



{ (("tls-sigalg-sec-bits")), (2), ((&xor_sigalg12.secbits)), (sizeof(unsigned int)), ((size_t)-1) },



{ (("tls-min-tls")), (1), ((&xor_sigalg12.mintls)), (sizeof(int)), ((size_t)-1) },



{ (("tls-max-tls")), (1), ((&xor_sigalg12.maxtls)), (sizeof(int)), ((size_t)-1) },



{ ((void*)0), 0, ((void*)0), 0, 0 }

};



static int tls_prov_get_capabilities(void *provctx, const char *capability,

OSSL_CALLBACK *cb, void *arg)

{

int ret = 0;

int i;

const char *dummy_base = "dummy";

const size_t dummy_name_max_size = strlen(dummy_base) + 3;



if (strcmp(capability, "TLS-GROUP") == 0) {



(void)((xor_group.group_id >= 65024 && xor_group.group_id < 65279 - 50) ? 0 : (OPENSSL_die("assertion failed: xor_group.group_id >= 65024 && xor_group.group_id < 65279 - NUM_DUMMY_GROUPS", "../test/tls-provider.c", 389), 1));



ret = cb(xor_group_params, arg);

ret &= cb(xor_kemgroup_params, arg);















for (i = 0; i < 50; i++) {

OSSL_PARAM dummygroup[(sizeof(xor_group_params)/sizeof((xor_group_params)[0]))];

unsigned int dummygroup_id;



memcpy(dummygroup, xor_group_params, sizeof(xor_group_params));





if (dummy_group_names[i] == ((void*)0)) {

dummy_group_names[i] = CRYPTO_zalloc(dummy_name_max_size, "../test/tls-provider.c", 407);

if (dummy_group_names[i] == ((void*)0))

return 0;

BIO_snprintf(dummy_group_names[i],

dummy_name_max_size,

"%s%d", dummy_base, i);

}

dummygroup[0].data = dummy_group_names[i];

dummygroup[0].data_size = strlen(dummy_group_names[i]) + 1;



dummygroup_id = 65279 - 50 + i;

dummygroup[3].data = (unsigned char*)&dummygroup_id;

ret &= cb(dummygroup, arg);

}

}



if (strcmp(capability, "TLS-SIGALG") == 0) {

ret = cb(xor_sig_nohash_params, arg);

ret &= cb(xor_sig_hash_params, arg);

ret &= cb(xor_sig_12_params, arg);

}

return ret;

}



typedef struct {

OSSL_LIB_CTX *libctx;

} PROV_XOR_CTX;



static PROV_XOR_CTX *xor_newprovctx(OSSL_LIB_CTX *libctx)

{

PROV_XOR_CTX* prov_ctx = CRYPTO_malloc(sizeof(PROV_XOR_CTX), "../test/tls-provider.c", 437);



if (prov_ctx == ((void*)0))

return ((void*)0);



if (libctx == ((void*)0)) {

CRYPTO_free(prov_ctx, "../test/tls-provider.c", 443);

return ((void*)0);

}

prov_ctx->libctx = libctx;

return prov_ctx;

}

// 459 "../test/tls-provider.c"

typedef struct {

XORKEY *key;

XORKEY *peerkey;

void *provctx;

} PROV_XORKEMKEX_CTX;



static void *xor_newkemkexctx(void *provctx)

{

PROV_XORKEMKEX_CTX *pxorctx = CRYPTO_zalloc(sizeof(PROV_XORKEMKEX_CTX), "../test/tls-provider.c", 467);



if (pxorctx == ((void*)0))

return ((void*)0);



pxorctx->provctx = provctx;



return pxorctx;

}



static int xor_init(void *vpxorctx, void *vkey,

const OSSL_PARAM params[])

{

PROV_XORKEMKEX_CTX *pxorctx = (PROV_XORKEMKEX_CTX *)vpxorctx;



if (pxorctx == ((void*)0) || vkey == ((void*)0))

return 0;

pxorctx->key = vkey;

return 1;

}



static int xor_set_peer(void *vpxorctx, void *vpeerkey)

{

PROV_XORKEMKEX_CTX *pxorctx = (PROV_XORKEMKEX_CTX *)vpxorctx;



if (pxorctx == ((void*)0) || vpeerkey == ((void*)0))

return 0;

pxorctx->peerkey = vpeerkey;

return 1;

}



static int xor_derive(void *vpxorctx, unsigned char *secret, size_t *secretlen,

size_t outlen)

{

PROV_XORKEMKEX_CTX *pxorctx = (PROV_XORKEMKEX_CTX *)vpxorctx;

int i;



if (pxorctx->key == ((void*)0) || pxorctx->peerkey == ((void*)0))

return 0;



*secretlen = 32;

if (secret == ((void*)0))

return 1;



if (outlen < 32)

return 0;



for (i = 0; i < 32; i++)

secret[i] = pxorctx->key->privkey[i] ^ pxorctx->peerkey->pubkey[i];



return 1;

}



static void xor_freectx(void *pxorctx)

{

CRYPTO_free(pxorctx, "../test/tls-provider.c", 522);

}



static void *xor_dupctx(void *vpxorctx)

{

PROV_XORKEMKEX_CTX *srcctx = (PROV_XORKEMKEX_CTX *)vpxorctx;

PROV_XORKEMKEX_CTX *dstctx;



dstctx = CRYPTO_zalloc(sizeof(*srcctx), "../test/tls-provider.c", 530);

if (dstctx == ((void*)0))

return ((void*)0);



*dstctx = *srcctx;



return dstctx;

}



static const OSSL_DISPATCH xor_keyexch_functions[] = {

{ 1, (void (*)(void))xor_newkemkexctx },

{ 2, (void (*)(void))xor_init },

{ 3, (void (*)(void))xor_derive },

{ 4, (void (*)(void))xor_set_peer },

{ 5, (void (*)(void))xor_freectx },

{ 6, (void (*)(void))xor_dupctx },

{ 0, ((void*)0) }

};



static const OSSL_ALGORITHM tls_prov_keyexch[] = {









{ "XOR", "provider=tls-provider,fips=yes", xor_keyexch_functions },

{ ((void*)0), ((void*)0), ((void*)0) }

};













static int xor_encapsulate(void *vpxorctx,

unsigned char *ct, size_t *ctlen,

unsigned char *ss, size_t *sslen)

{

// 575 "../test/tls-provider.c"

int rv = 0;

void *genctx = ((void*)0), *derivectx = ((void*)0);

XORKEY *ourkey = ((void*)0);

PROV_XORKEMKEX_CTX *pxorctx = vpxorctx;



if (ct == ((void*)0) || ss == ((void*)0)) {





if (ctlen == ((void*)0) && sslen == ((void*)0))

return 0;

if (ctlen != ((void*)0))

*ctlen = 32;

if (sslen != ((void*)0))

*sslen = 32;

return 1;

}





genctx = xor_gen_init(pxorctx->provctx, ( 0x01 | 0x02 ), ((void*)0));

if (genctx == ((void*)0))

goto end;

ourkey = xor_gen(genctx, ((void*)0), ((void*)0));

if (ourkey == ((void*)0))

goto end;





memcpy(ct, ourkey->pubkey, 32);

*ctlen = 32;





derivectx = xor_newkemkexctx(pxorctx->provctx);

if (derivectx == ((void*)0)

|| !xor_init(derivectx, ourkey, ((void*)0))

|| !xor_set_peer(derivectx, pxorctx->key)

|| !xor_derive(derivectx, ss, sslen, 32))

goto end;



rv = 1;



end:

xor_gen_cleanup(genctx);

xor_freekey(ourkey);

xor_freectx(derivectx);

return rv;

}



static int xor_decapsulate(void *vpxorctx,

unsigned char *ss, size_t *sslen,

const unsigned char *ct, size_t ctlen)

{













int rv = 0;

void *derivectx = ((void*)0);

XORKEY *peerkey = ((void*)0);

PROV_XORKEMKEX_CTX *pxorctx = vpxorctx;



if (ss == ((void*)0)) {



if (sslen == ((void*)0))

return 0;

*sslen = 32;

return 1;

}



if (ctlen != 32)

return 0;

peerkey = xor_newkey(pxorctx->provctx);

if (peerkey == ((void*)0))

goto end;

memcpy(peerkey->pubkey, ct, 32);





derivectx = xor_newkemkexctx(pxorctx->provctx);

if (derivectx == ((void*)0)

|| !xor_init(derivectx, pxorctx->key, ((void*)0))

|| !xor_set_peer(derivectx, peerkey)

|| !xor_derive(derivectx, ss, sslen, 32))

goto end;



rv = 1;



end:

xor_freekey(peerkey);

xor_freectx(derivectx);

return rv;

}



static const OSSL_DISPATCH xor_kem_functions[] = {

{ 1, (void (*)(void))xor_newkemkexctx },

{ 6, (void (*)(void))xor_freectx },

{ 7, (void (*)(void))xor_dupctx },

{ 2, (void (*)(void))xor_init },

{ 3, (void (*)(void))xor_encapsulate },

{ 4, (void (*)(void))xor_init },

{ 5, (void (*)(void))xor_decapsulate },

{ 0, ((void*)0) }

};



static const OSSL_ALGORITHM tls_prov_kem[] = {









{ "XOR", "provider=tls-provider,fips=yes", xor_kem_functions },

{ ((void*)0), ((void*)0), ((void*)0) }

};







static void *xor_newkey(void *provctx)

{

XORKEY *ret = CRYPTO_zalloc(sizeof(XORKEY), "../test/tls-provider.c", 691);



if (ret == ((void*)0))

return ((void*)0);



if (!CRYPTO_NEW_REF(&ret->references, 1)) {

CRYPTO_free(ret, "../test/tls-provider.c", 697);

return ((void*)0);

}



return ret;

}



static void xor_freekey(void *keydata)

{

XORKEY* key = (XORKEY *)keydata;

int refcnt;



if (key == ((void*)0))

return;



if (CRYPTO_DOWN_REF(&key->references, &refcnt) <= 0)

return;



if (refcnt > 0)

return;

((void) (0));



if (key != ((void*)0)) {

CRYPTO_free(key->tls_name, "../test/tls-provider.c", 720);

key->tls_name = ((void*)0);

}

CRYPTO_FREE_REF(&key->references);

CRYPTO_free(key, "../test/tls-provider.c", 724);

}



static int xor_key_up_ref(XORKEY *key)

{

int refcnt;



if (CRYPTO_UP_REF(&key->references, &refcnt) <= 0)

return 0;



((void) (0));

return (refcnt > 1);

}



static int xor_has(const void *vkey, int selection)

{

const XORKEY *key = vkey;

int ok = 0;



if (key != ((void*)0)) {

ok = 1;



if ((selection & 0x02) != 0)

ok = ok && key->haspubkey;

if ((selection & 0x01) != 0)

ok = ok && key->hasprivkey;

}

return ok;

}



static void *xor_dup(const void *vfromkey, int selection)

{

XORKEY *tokey = xor_newkey(((void*)0));

const XORKEY *fromkey = vfromkey;

int ok = 0;



if (tokey != ((void*)0) && fromkey != ((void*)0)) {

ok = 1;



if ((selection & 0x02) != 0) {

if (fromkey->haspubkey) {

memcpy(tokey->pubkey, fromkey->pubkey, 32);

tokey->haspubkey = 1;

} else {

tokey->haspubkey = 0;

}

}

if ((selection & 0x01) != 0) {

if (fromkey->hasprivkey) {

memcpy(tokey->privkey, fromkey->privkey, 32);

tokey->hasprivkey = 1;

} else {

tokey->hasprivkey = 0;

}

}

if (fromkey->tls_name != ((void*)0))

tokey->tls_name = CRYPTO_strdup(fromkey->tls_name, "../test/tls-provider.c", 780);

}

if (!ok) {

xor_freekey(tokey);

tokey = ((void*)0);

}

return tokey;

}



static inline int xor_get_params(void *vkey, OSSL_PARAM params[])

{

XORKEY *key = vkey;

OSSL_PARAM *p;



if ((p = OSSL_PARAM_locate(params, "bits")) != ((void*)0)

&& !OSSL_PARAM_set_int(p, 32))

return 0;



if ((p = OSSL_PARAM_locate(params, "security-bits")) != ((void*)0)

&& !OSSL_PARAM_set_int(p, xor_group.secbits))

return 0;



if ((p = OSSL_PARAM_locate(params,

"encoded-pub-key")) != ((void*)0)) {

if (p->data_type != 5)

return 0;

p->return_size = 32;

if (p->data != ((void*)0) && p->data_size >= 32)

memcpy(p->data, key->pubkey, 32);

}



return 1;

}



static const OSSL_PARAM xor_params[] = {

{ (("bits")), (1), ((((void*)0))), (sizeof(int)), ((size_t)-1) },

{ (("security-bits")), (1), ((((void*)0))), (sizeof(int)), ((size_t)-1) },

{ (("encoded-pub-key")), (5), ((((void*)0))), (0), ((size_t)-1) },

{ ((void*)0), 0, ((void*)0), 0, 0 }

};



static const OSSL_PARAM *xor_gettable_params(void *provctx)

{

return xor_params;

}



static int xor_set_params(void *vkey, const OSSL_PARAM params[])

{

XORKEY *key = vkey;

const OSSL_PARAM *p;



p = OSSL_PARAM_locate_const(params, "encoded-pub-key");

if (p != ((void*)0)) {

if (p->data_type != 5

|| p->data_size != 32)

return 0;

memcpy(key->pubkey, p->data, 32);

key->haspubkey = 1;

}



return 1;

}



static const OSSL_PARAM xor_known_settable_params[] = {

{ (("encoded-pub-key")), (5), ((((void*)0))), (0), ((size_t)-1) },

{ ((void*)0), 0, ((void*)0), 0, 0 }

};



static void *xor_load(const void *reference, size_t reference_sz)

{

XORKEY *key = ((void*)0);



if (reference_sz == sizeof(key)) {



key = *(XORKEY **)reference;



*(XORKEY **)reference = ((void*)0);

return key;

}

return ((void*)0);

}





static int xor_recreate(const unsigned char *kd1, const unsigned char *kd2) {

int i;



for (i = 0; i < 32; i++) {

if ((kd1[i] & 0xff) != ((kd2[i] ^ private_constant[i]) & 0xff))

return 0;

}

return 1;

}



static int xor_match(const void *keydata1, const void *keydata2, int selection)

{

const XORKEY *key1 = keydata1;

const XORKEY *key2 = keydata2;

int ok = 1;



if (key1->tls_name != ((void*)0) && key2->tls_name != ((void*)0))

ok = ok & (strcmp(key1->tls_name, key2->tls_name) == 0);



if ((selection & 0x01) != 0) {

if (key1->hasprivkey) {

if (key2->hasprivkey)

ok = ok & (CRYPTO_memcmp(key1->privkey, key2->privkey,

32) == 0);

else

ok = ok & xor_recreate(key1->privkey, key2->pubkey);

} else {

if (key2->hasprivkey)

ok = ok & xor_recreate(key2->privkey, key1->pubkey);

else

ok = 0;

}

}



if ((selection & 0x02) != 0) {

if (key1->haspubkey) {

if (key2->haspubkey)

ok = ok & (CRYPTO_memcmp(key1->pubkey, key2->pubkey, 32) == 0);

else

ok = ok & xor_recreate(key1->pubkey, key2->privkey);

} else {

if (key2->haspubkey)

ok = ok & xor_recreate(key2->pubkey, key1->privkey);

else

ok = 0;

}

}



return ok;

}



static const OSSL_PARAM *xor_settable_params(void *provctx)

{

return xor_known_settable_params;

}



struct xor_gen_ctx {

int selection;

OSSL_LIB_CTX *libctx;

};



static void *xor_gen_init(void *provctx, int selection,

const OSSL_PARAM params[])

{

struct xor_gen_ctx *gctx = ((void*)0);



if ((selection & (( 0x01 | 0x02 )

| 0x04)) == 0)

return ((void*)0);



if ((gctx = CRYPTO_zalloc(sizeof(*gctx), "../test/tls-provider.c", 933)) != ((void*)0))

gctx->selection = selection;



gctx->libctx = (((PROV_XOR_CTX *)provctx)->libctx);



if (!xor_gen_set_params(gctx, params)) {

CRYPTO_free(gctx, "../test/tls-provider.c", 939);

return ((void*)0);

}

return gctx;

}



static int xor_gen_set_params(void *genctx, const OSSL_PARAM params[])

{

struct xor_gen_ctx *gctx = genctx;

const OSSL_PARAM *p;



if (gctx == ((void*)0))

return 0;



p = OSSL_PARAM_locate_const(params, "group");

if (p != ((void*)0)) {

if (p->data_type != 4

|| (strcmp(p->data, "xorgroup-int") != 0

&& strcmp(p->data, "xorkemgroup-int") != 0))

return 0;

}



return 1;

}



static const OSSL_PARAM *xor_gen_settable_params( void *genctx,

void *provctx)

{

static OSSL_PARAM settable[] = {

{ (("group")), (4), ((((void*)0))), (0), ((size_t)-1) },

{ ((void*)0), 0, ((void*)0), 0, 0 }

};

return settable;

}



static void *xor_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)

{

struct xor_gen_ctx *gctx = genctx;

XORKEY *key = xor_newkey(((void*)0));

size_t i;



if (key == ((void*)0))

return ((void*)0);



if ((gctx->selection & ( 0x01 | 0x02 )) != 0) {

if (RAND_bytes_ex(gctx->libctx, key->privkey, 32, 0) <= 0) {

CRYPTO_free(key, "../test/tls-provider.c", 985);

return ((void*)0);

}

for (i = 0; i < 32; i++)

key->pubkey[i] = key->privkey[i] ^ private_constant[i];

key->hasprivkey = 1;

key->haspubkey = 1;

}



return key;

}







static int xor_import(void *vkey, int select, const OSSL_PARAM params[])

{

XORKEY *key = vkey;

const OSSL_PARAM *param_priv_key, *param_pub_key;

unsigned char privkey[32];

unsigned char pubkey[32];

void *pprivkey = privkey, *ppubkey = pubkey;

size_t priv_len = 0, pub_len = 0;

int res = 0;



if (key == ((void*)0) || (select & ( 0x01 | 0x02 )) == 0)

return 0;



memset(privkey, 0, sizeof(privkey));

memset(pubkey, 0, sizeof(pubkey));

param_priv_key = OSSL_PARAM_locate_const(params, "priv");

param_pub_key = OSSL_PARAM_locate_const(params, "pub");



if ((param_priv_key != ((void*)0)

&& !OSSL_PARAM_get_octet_string(param_priv_key, &pprivkey,

sizeof(privkey), &priv_len))

|| (param_pub_key != ((void*)0)

&& !OSSL_PARAM_get_octet_string(param_pub_key, &ppubkey,

sizeof(pubkey), &pub_len)))

goto err;



if (priv_len > 0) {

memcpy(key->privkey, privkey, priv_len);

key->hasprivkey = 1;

}

if (pub_len > 0) {

memcpy(key->pubkey, pubkey, pub_len);

key->haspubkey = 1;

}

res = 1;

err:

return res;

}



static int xor_export(void *vkey, int select, OSSL_CALLBACK *param_cb,

void *cbarg)

{

XORKEY *key = vkey;

OSSL_PARAM params[3], *p = params;



if (key == ((void*)0) || (select & ( 0x01 | 0x02 )) == 0)

return 0;



*p++ = OSSL_PARAM_construct_octet_string("priv",

key->privkey,

sizeof(key->privkey));

*p++ = OSSL_PARAM_construct_octet_string("pub",

key->pubkey, sizeof(key->pubkey));

*p++ = OSSL_PARAM_construct_end();



return param_cb(params, cbarg);

}



static const OSSL_PARAM xor_key_types[] = {

{ (("pub")), (2), ((((void*)0))), ((0)), ((size_t)-1) },

{ (("priv")), (2), ((((void*)0))), ((0)), ((size_t)-1) },

{ ((void*)0), 0, ((void*)0), 0, 0 }

};



static const OSSL_PARAM *xor_import_types(int select)

{

return (select & ( 0x01 | 0x02 )) != 0 ? xor_key_types : ((void*)0);

}



static const OSSL_PARAM *xor_import_types_ex(void *provctx, int select)

{

if (provctx == ((void*)0))

return ((void*)0);



return xor_import_types(select);

}



static const OSSL_PARAM *xor_export_types(int select)

{

return (select & ( 0x01 | 0x02 )) != 0 ? xor_key_types : ((void*)0);

}



static const OSSL_PARAM *xor_export_types_ex(void *provctx, int select)

{

if (provctx == ((void*)0))

return ((void*)0);



return xor_export_types(select);

}



static void xor_gen_cleanup(void *genctx)

{

CRYPTO_free(genctx, "../test/tls-provider.c", 1091);

}



static const OSSL_DISPATCH xor_keymgmt_functions[] = {

{ 1, (void (*)(void))xor_newkey },

{ 2, (void (*)(void))xor_gen_init },

{ 4, (void (*)(void))xor_gen_set_params },

{ 5,

(void (*)(void))xor_gen_settable_params },

{ 6, (void (*)(void))xor_gen },

{ 7, (void (*)(void))xor_gen_cleanup },

{ 11, (void (*) (void))xor_get_params },

{ 12, (void (*) (void))xor_gettable_params },

{ 13, (void (*) (void))xor_set_params },

{ 14, (void (*) (void))xor_settable_params },

{ 21, (void (*)(void))xor_has },

{ 44, (void (*)(void))xor_dup },

{ 10, (void (*)(void))xor_freekey },

{ 40, (void (*)(void))xor_import },

{ 41, (void (*)(void))xor_import_types },

{ 45, (void (*)(void))xor_import_types_ex },

{ 42, (void (*)(void))xor_export },

{ 43, (void (*)(void))xor_export_types },

{ 46, (void (*)(void))xor_export_types_ex },

{ 0, ((void*)0) }

};





static void *xor_xorhmacsig_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)

{

XORKEY *k = xor_gen(genctx, osslcb, cbarg);



if (k == ((void*)0))

return ((void*)0);

k->tls_name = CRYPTO_strdup("xorhmacsig", "../test/tls-provider.c", 1125);

if (k->tls_name == ((void*)0)) {

xor_freekey(k);

return ((void*)0);

}

return k;

}



static void *xor_xorhmacsha2sig_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)

{

XORKEY* k = xor_gen(genctx, osslcb, cbarg);



if (k == ((void*)0))

return ((void*)0);

k->tls_name = CRYPTO_strdup("xorhmacsha2sig", "../test/tls-provider.c", 1139);

if (k->tls_name == ((void*)0)) {

xor_freekey(k);

return ((void*)0);

}

return k;

}





static const OSSL_DISPATCH xor_xorhmacsig_keymgmt_functions[] = {

{ 1, (void (*)(void))xor_newkey },

{ 2, (void (*)(void))xor_gen_init },

{ 4, (void (*)(void))xor_gen_set_params },

{ 5,

(void (*)(void))xor_gen_settable_params },

{ 6, (void (*)(void))xor_xorhmacsig_gen },

{ 7, (void (*)(void))xor_gen_cleanup },

{ 11, (void (*) (void))xor_get_params },

{ 12, (void (*) (void))xor_gettable_params },

{ 13, (void (*) (void))xor_set_params },

{ 14, (void (*) (void))xor_settable_params },

{ 21, (void (*)(void))xor_has },

{ 44, (void (*)(void))xor_dup },

{ 10, (void (*)(void))xor_freekey },

{ 40, (void (*)(void))xor_import },

{ 41, (void (*)(void))xor_import_types },

{ 42, (void (*)(void))xor_export },

{ 43, (void (*)(void))xor_export_types },

{ 8, (void (*)(void))xor_load },

{ 23, (void (*)(void))xor_match },

{ 0, ((void*)0) }

};



static const OSSL_DISPATCH xor_xorhmacsha2sig_keymgmt_functions[] = {

{ 1, (void (*)(void))xor_newkey },

{ 2, (void (*)(void))xor_gen_init },

{ 4, (void (*)(void))xor_gen_set_params },

{ 5,

(void (*)(void))xor_gen_settable_params },

{ 6, (void (*)(void))xor_xorhmacsha2sig_gen },

{ 7, (void (*)(void))xor_gen_cleanup },

{ 11, (void (*) (void))xor_get_params },

{ 12, (void (*) (void))xor_gettable_params },

{ 13, (void (*) (void))xor_set_params },

{ 14, (void (*) (void))xor_settable_params },

{ 21, (void (*)(void))xor_has },

{ 44, (void (*)(void))xor_dup },

{ 10, (void (*)(void))xor_freekey },

{ 40, (void (*)(void))xor_import },

{ 41, (void (*)(void))xor_import_types },

{ 42, (void (*)(void))xor_export },

{ 43, (void (*)(void))xor_export_types },

{ 8, (void (*)(void))xor_load },

{ 23, (void (*)(void))xor_match },

{ 0, ((void*)0) }

};



typedef enum {

KEY_OP_PUBLIC,

KEY_OP_PRIVATE,

KEY_OP_KEYGEN

} xor_key_op_t;





static XORKEY *xor_key_op(const X509_ALGOR *palg,

const unsigned char *p, int plen,

xor_key_op_t op,

OSSL_LIB_CTX *libctx, const char *propq)

{

XORKEY *key = ((void*)0);

int nid = 0;



if (palg != ((void*)0)) {

int ptype;





X509_ALGOR_get0(((void*)0), &ptype, ((void*)0), palg);

if (ptype != -1 || palg->algorithm == ((void*)0)) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1217,__func__), ERR_set_error)((128),(7),((void*)0));

return 0;

}

nid = OBJ_obj2nid(palg->algorithm);

}



if (p == ((void*)0) || nid == 0 || nid == 0) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1224,__func__), ERR_set_error)((128),(7),((void*)0));

return 0;

}



key = xor_newkey(((void*)0));

if (key == ((void*)0)) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1230,__func__), ERR_set_error)((128),((256|((0x1 << 18L)|(0x2 << 18L)))),((void*)0));

return 0;

}



if (32 != plen) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1235,__func__), ERR_set_error)((128),(7),((void*)0));

goto err;

}



if (op == KEY_OP_PUBLIC) {

memcpy(key->pubkey, p, plen);

key->haspubkey = 1;

} else {

memcpy(key->privkey, p, plen);

key->hasprivkey = 1;

}



key->tls_name = CRYPTO_strdup(OBJ_nid2sn(nid), "../test/tls-provider.c", 1247);

if (key->tls_name == ((void*)0))

goto err;

return key;



err:

xor_freekey(key);

return ((void*)0);

}



static XORKEY *xor_key_from_x509pubkey(const X509_PUBKEY *xpk,

OSSL_LIB_CTX *libctx, const char *propq)

{

const unsigned char *p;

int plen;

X509_ALGOR *palg;



if (!xpk || (!X509_PUBKEY_get0_param(((void*)0), &p, &plen, &palg, xpk))) {

return ((void*)0);

}

return xor_key_op(palg, p, plen, KEY_OP_PUBLIC, libctx, propq);

}



static XORKEY *xor_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,

OSSL_LIB_CTX *libctx, const char *propq)

{

XORKEY *xork = ((void*)0);

const unsigned char *p;

int plen;

ASN1_OCTET_STRING *oct = ((void*)0);

const X509_ALGOR *palg;



if (!PKCS8_pkey_get0(((void*)0), &p, &plen, &palg, p8inf))

return 0;



oct = d2i_ASN1_OCTET_STRING(((void*)0), &p, plen);

if (oct == ((void*)0)) {

p = ((void*)0);

plen = 0;

} else {

p = ASN1_STRING_get0_data(oct);

plen = ASN1_STRING_length(oct);

}



xork = xor_key_op(palg, p, plen, KEY_OP_PRIVATE,

libctx, propq);

ASN1_OCTET_STRING_free(oct);

return xork;

}



static const OSSL_ALGORITHM tls_prov_keymgmt[] = {









{ "XOR", "provider=tls-provider,fips=yes",

xor_keymgmt_functions },

{ "xorhmacsig", "provider=tls-provider,fips=yes",

xor_xorhmacsig_keymgmt_functions },

{ "xorhmacsha2sig",

"provider=tls-provider,fips=yes",

xor_xorhmacsha2sig_keymgmt_functions },

{ ((void*)0), ((void*)0), ((void*)0) }

};



struct key2any_ctx_st {

PROV_XOR_CTX *provctx;





int save_parameters;





int cipher_intent;



EVP_CIPHER *cipher;



OSSL_PASSPHRASE_CALLBACK *pwcb;

void *pwcbarg;

};



typedef int check_key_type_fn(const void *key, int nid);

typedef int key_to_paramstring_fn(const void *key, int nid, int save,

void **str, int *strtype);

typedef int key_to_der_fn(BIO *out, const void *key,

int key_nid, const char *pemname,

key_to_paramstring_fn *p2s, i2d_of_void *k2d,

struct key2any_ctx_st *ctx);

typedef int write_bio_of_void_fn(BIO *bp, const void *x);







static void free_asn1_data(int type, void *data)

{

switch(type) {

case 6:

ASN1_OBJECT_free(data);

break;

case 16:

ASN1_STRING_free(data);

break;

}

}



static PKCS8_PRIV_KEY_INFO *key_to_p8info(const void *key, int key_nid,

void *params, int params_type,

i2d_of_void *k2d)

{



unsigned char *der = ((void*)0);

int derlen;



PKCS8_PRIV_KEY_INFO *p8info = ((void*)0);



if ((p8info = PKCS8_PRIV_KEY_INFO_new()) == ((void*)0)

|| (derlen = k2d(key, &der)) <= 0

|| !PKCS8_pkey_set0(p8info, OBJ_nid2obj(key_nid), 0,

-1, ((void*)0),

der, derlen)) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1365,__func__), ERR_set_error)((128),((256|((0x1 << 18L)|(0x2 << 18L)))),((void*)0));

PKCS8_PRIV_KEY_INFO_free(p8info);

CRYPTO_free(der, "../test/tls-provider.c", 1367);

p8info = ((void*)0);

}



return p8info;

}



static X509_SIG *p8info_to_encp8(PKCS8_PRIV_KEY_INFO *p8info,

struct key2any_ctx_st *ctx)

{

X509_SIG *p8 = ((void*)0);

char kstr[1024];

size_t klen = 0;

OSSL_LIB_CTX *libctx = (((PROV_XOR_CTX *)ctx->provctx)->libctx);



if (ctx->cipher == ((void*)0) || ctx->pwcb == ((void*)0))

return ((void*)0);



if (!ctx->pwcb(kstr, 1024, &klen, ((void*)0), ctx->pwcbarg)) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1386,__func__), ERR_set_error)((128),(159),((void*)0));

return ((void*)0);

}



p8 = PKCS8_encrypt_ex(-1, ctx->cipher, kstr, klen, ((void*)0), 0, 0, p8info, libctx, ((void*)0));

OPENSSL_cleanse(kstr, klen);

return p8;

}



static X509_SIG *key_to_encp8(const void *key, int key_nid,

void *params, int params_type,

i2d_of_void *k2d, struct key2any_ctx_st *ctx)

{

PKCS8_PRIV_KEY_INFO *p8info =

key_to_p8info(key, key_nid, params, params_type, k2d);

X509_SIG *p8 = ((void*)0);



if (p8info == ((void*)0)) {

free_asn1_data(params_type, params);

} else {

p8 = p8info_to_encp8(p8info, ctx);

PKCS8_PRIV_KEY_INFO_free(p8info);

}

return p8;

}



static X509_PUBKEY *xorx_key_to_pubkey(const void *key, int key_nid,

void *params, int params_type,

i2d_of_void k2d)

{



unsigned char *der = ((void*)0);

int derlen;



X509_PUBKEY *xpk = ((void*)0);



if ((xpk = X509_PUBKEY_new()) == ((void*)0)

|| (derlen = k2d(key, &der)) <= 0

|| !X509_PUBKEY_set0_param(xpk, OBJ_nid2obj(key_nid),

-1, ((void*)0),

der, derlen)) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1427,__func__), ERR_set_error)((128),((256|((0x1 << 18L)|(0x2 << 18L)))),((void*)0));

X509_PUBKEY_free(xpk);

CRYPTO_free(der, "../test/tls-provider.c", 1429);

xpk = ((void*)0);

}



return xpk;

}

// 1455 "../test/tls-provider.c"

static int key_to_epki_der_priv_bio(BIO *out, const void *key,

int key_nid,

const char *pemname,

key_to_paramstring_fn *p2s,

i2d_of_void *k2d,

struct key2any_ctx_st *ctx)

{

int ret = 0;

void *str = ((void*)0);

int strtype = -1;

X509_SIG *p8;



if (!ctx->cipher_intent)

return 0;



if (p2s != ((void*)0) && !p2s(key, key_nid, ctx->save_parameters,

&str, &strtype))

return 0;



p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);

if (p8 != ((void*)0))

ret = i2d_PKCS8_bio(out, p8);



X509_SIG_free(p8);



return ret;

}



static int key_to_epki_pem_priv_bio(BIO *out, const void *key,

int key_nid,

const char *pemname,

key_to_paramstring_fn *p2s,

i2d_of_void *k2d,

struct key2any_ctx_st *ctx)

{

int ret = 0;

void *str = ((void*)0);

int strtype = -1;

X509_SIG *p8;



if (!ctx->cipher_intent)

return 0;



if (p2s != ((void*)0) && !p2s(key, key_nid, ctx->save_parameters,

&str, &strtype))

return 0;



p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);

if (p8 != ((void*)0))

ret = PEM_write_bio_PKCS8(out, p8);



X509_SIG_free(p8);



return ret;

}



static int key_to_pki_der_priv_bio(BIO *out, const void *key,

int key_nid,

const char *pemname,

key_to_paramstring_fn *p2s,

i2d_of_void *k2d,

struct key2any_ctx_st *ctx)

{

int ret = 0;

void *str = ((void*)0);

int strtype = -1;

PKCS8_PRIV_KEY_INFO *p8info;



if (ctx->cipher_intent)

return key_to_epki_der_priv_bio(out, key, key_nid, pemname,

p2s, k2d, ctx);



if (p2s != ((void*)0) && !p2s(key, key_nid, ctx->save_parameters,

&str, &strtype))

return 0;



p8info = key_to_p8info(key, key_nid, str, strtype, k2d);



if (p8info != ((void*)0))

ret = i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8info);

else

free_asn1_data(strtype, str);



PKCS8_PRIV_KEY_INFO_free(p8info);



return ret;

}



static int key_to_pki_pem_priv_bio(BIO *out, const void *key,

int key_nid,

const char *pemname,

key_to_paramstring_fn *p2s,

i2d_of_void *k2d,

struct key2any_ctx_st *ctx)

{

int ret = 0;

void *str = ((void*)0);

int strtype = -1;

PKCS8_PRIV_KEY_INFO *p8info;



if (ctx->cipher_intent)

return key_to_epki_pem_priv_bio(out, key, key_nid, pemname,

p2s, k2d, ctx);



if (p2s != ((void*)0) && !p2s(key, key_nid, ctx->save_parameters,

&str, &strtype))

return 0;



p8info = key_to_p8info(key, key_nid, str, strtype, k2d);



if (p8info != ((void*)0))

ret = PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info);

else

free_asn1_data(strtype, str);



PKCS8_PRIV_KEY_INFO_free(p8info);



return ret;

}



static int key_to_spki_der_pub_bio(BIO *out, const void *key,

int key_nid,

const char *pemname,

key_to_paramstring_fn *p2s,

i2d_of_void *k2d,

struct key2any_ctx_st *ctx)

{

int ret = 0;

X509_PUBKEY *xpk = ((void*)0);

void *str = ((void*)0);

int strtype = -1;



if (p2s != ((void*)0) && !p2s(key, key_nid, ctx->save_parameters,

&str, &strtype))

return 0;



xpk = xorx_key_to_pubkey(key, key_nid, str, strtype, k2d);



if (xpk != ((void*)0))

ret = i2d_X509_PUBKEY_bio(out, xpk);



X509_PUBKEY_free(xpk);

return ret;

}



static int key_to_spki_pem_pub_bio(BIO *out, const void *key,

int key_nid,

const char *pemname,

key_to_paramstring_fn *p2s,

i2d_of_void *k2d,

struct key2any_ctx_st *ctx)

{

int ret = 0;

X509_PUBKEY *xpk = ((void*)0);

void *str = ((void*)0);

int strtype = -1;



if (p2s != ((void*)0) && !p2s(key, key_nid, ctx->save_parameters,

&str, &strtype))

return 0;



xpk = xorx_key_to_pubkey(key, key_nid, str, strtype, k2d);



if (xpk != ((void*)0))

ret = PEM_write_bio_X509_PUBKEY(out, xpk);

else

free_asn1_data(strtype, str);





X509_PUBKEY_free(xpk);

return ret;

}







static int prepare_xorx_params(const void *xorxkey, int nid, int save,

void **pstr, int *pstrtype)

{

ASN1_OBJECT *params = ((void*)0);

XORKEY *k = (XORKEY*)xorxkey;



if (k->tls_name && OBJ_sn2nid(k->tls_name) != nid) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1637,__func__), ERR_set_error)((128),(3),((void*)0));

return 0;

}



if (nid == 0) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1642,__func__), ERR_set_error)((128),(5),((void*)0));

return 0;

}



params = OBJ_nid2obj(nid);



if (params == ((void*)0) || OBJ_length(params) == 0) {



(ERR_new(), ERR_set_debug("../test/tls-provider.c",1650,__func__), ERR_set_error)((128),(5),((void*)0));

ASN1_OBJECT_free(params);

return 0;

}

*pstr = params;

*pstrtype = 6;

return 1;

}



static int xorx_spki_pub_to_der(const void *vecxkey, unsigned char **pder)

{

const XORKEY *xorxkey = vecxkey;

unsigned char *keyblob;

int retlen;



if (xorxkey == ((void*)0)) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1666,__func__), ERR_set_error)((128),((258|((0x1 << 18L)|(0x2 << 18L)))),((void*)0));

return 0;

}



keyblob = CRYPTO_memdup((xorxkey->pubkey), retlen = 32, "../test/tls-provider.c", 1670);

if (keyblob == ((void*)0)) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1672,__func__), ERR_set_error)((128),((256|((0x1 << 18L)|(0x2 << 18L)))),((void*)0));

return 0;

}



*pder = keyblob;

return retlen;

}



static int xorx_pki_priv_to_der(const void *vecxkey, unsigned char **pder)

{

XORKEY *xorxkey = (XORKEY *)vecxkey;

unsigned char* buf = ((void*)0);

ASN1_OCTET_STRING oct;

int keybloblen;



if (xorxkey == ((void*)0)) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1688,__func__), ERR_set_error)((128),((258|((0x1 << 18L)|(0x2 << 18L)))),((void*)0));

return 0;

}



buf = CRYPTO_secure_malloc(32, "../test/tls-provider.c", 1692);

memcpy(buf, xorxkey->privkey, 32);



oct.data = buf;

oct.length = 32;

oct.flags = 0;



keybloblen = i2d_ASN1_OCTET_STRING(&oct, pder);

if (keybloblen < 0) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1701,__func__), ERR_set_error)((128),((256|((0x1 << 18L)|(0x2 << 18L)))),((void*)0));

keybloblen = 0;

}



CRYPTO_secure_clear_free(buf, 32, "../test/tls-provider.c", 1705);

return keybloblen;

}

// 1727 "../test/tls-provider.c"

static OSSL_FUNC_decoder_newctx_fn key2any_newctx;

static OSSL_FUNC_decoder_freectx_fn key2any_freectx;



static void *key2any_newctx(void *provctx)

{

struct key2any_ctx_st *ctx = CRYPTO_zalloc(sizeof(*ctx), "../test/tls-provider.c", 1732);



if (ctx != ((void*)0)) {

ctx->provctx = provctx;

ctx->save_parameters = 1;

}



return ctx;

}



static void key2any_freectx(void *vctx)

{

struct key2any_ctx_st *ctx = vctx;



EVP_CIPHER_free(ctx->cipher);

CRYPTO_free(ctx, "../test/tls-provider.c", 1747);

}



static const OSSL_PARAM *key2any_settable_ctx_params( void *provctx)

{

static const OSSL_PARAM settables[] = {

{ (("cipher")), (4), ((((void*)0))), (0), ((size_t)-1) },

{ (("properties")), (4), ((((void*)0))), (0), ((size_t)-1) },

{ ((void*)0), 0, ((void*)0), 0, 0 },

};



return settables;

}



static int key2any_set_ctx_params(void *vctx, const OSSL_PARAM params[])

{

struct key2any_ctx_st *ctx = vctx;

OSSL_LIB_CTX *libctx = (((PROV_XOR_CTX *)ctx->provctx)->libctx);

const OSSL_PARAM *cipherp =

OSSL_PARAM_locate_const(params, "cipher");

const OSSL_PARAM *propsp =

OSSL_PARAM_locate_const(params, "properties");

const OSSL_PARAM *save_paramsp =

OSSL_PARAM_locate_const(params, "save-parameters");



if (cipherp != ((void*)0)) {

const char *ciphername = ((void*)0);

const char *props = ((void*)0);



if (!OSSL_PARAM_get_utf8_string_ptr(cipherp, &ciphername))

return 0;

if (propsp != ((void*)0) && !OSSL_PARAM_get_utf8_string_ptr(propsp, &props))

return 0;



EVP_CIPHER_free(ctx->cipher);

ctx->cipher = ((void*)0);

ctx->cipher_intent = ciphername != ((void*)0);

if (ciphername != ((void*)0)

&& ((ctx->cipher =

EVP_CIPHER_fetch(libctx, ciphername, props)) == ((void*)0))) {

return 0;

}

}



if (save_paramsp != ((void*)0)) {

if (!OSSL_PARAM_get_int(save_paramsp, &ctx->save_parameters)) {

return 0;

}

}

return 1;

}



static int key2any_check_selection(int selection, int selection_mask)

{









int checks[] = {

0x01,

0x02,

( 0x04 | 0x80)

};

size_t i;





if (selection == 0)

return 1;



for (i = 0; i < (sizeof(checks)/sizeof((checks)[0])); i++) {

int check1 = (selection & checks[i]) != 0;

int check2 = (selection_mask & checks[i]) != 0;











if (check1)

return check2;

}





return 0;

}



static int key2any_encode(struct key2any_ctx_st *ctx, OSSL_CORE_BIO *cout,

const void *key, const char* typestr, const char *pemname,

key_to_der_fn *writer,

OSSL_PASSPHRASE_CALLBACK *pwcb, void *pwcbarg,

key_to_paramstring_fn *key2paramstring,

i2d_of_void *key2der)

{

int ret = 0;

int type = OBJ_sn2nid(typestr);



if (key == ((void*)0) || type <= 0) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1843,__func__), ERR_set_error)((128),((258|((0x1 << 18L)|(0x2 << 18L)))),((void*)0));

} else if (writer != ((void*)0)) {

BIO *out = BIO_new_from_core_bio(ctx->provctx->libctx, cout);



if (out != ((void*)0)) {

ctx->pwcb = pwcb;

ctx->pwcbarg = pwcbarg;



ret = writer(out, key, type, pemname, key2paramstring, key2der, ctx);

}



BIO_free(out);

} else {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",1856,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0));

}

return ret;

}

// 2031 "../test/tls-provider.c"

static OSSL_FUNC_encoder_import_object_fn xorhmacsig_to_EncryptedPrivateKeyInfo_der_import_object; static OSSL_FUNC_encoder_free_object_fn xorhmacsig_to_EncryptedPrivateKeyInfo_der_free_object; static OSSL_FUNC_encoder_encode_fn xorhmacsig_to_EncryptedPrivateKeyInfo_der_encode; static void * xorhmacsig_to_EncryptedPrivateKeyInfo_der_import_object(void *vctx, int selection, const OSSL_PARAM params[]) { struct key2any_ctx_st *ctx = vctx; return xor_prov_import_key(xor_xorhmacsig_keymgmt_functions, ctx->provctx, selection, params); } static void xorhmacsig_to_EncryptedPrivateKeyInfo_der_free_object(void *key) { xor_prov_free_key(xor_xorhmacsig_keymgmt_functions, key); } static int xorhmacsig_to_EncryptedPrivateKeyInfo_der_does_selection(void *ctx, int selection) { return key2any_check_selection(selection, 0x01); } static int xorhmacsig_to_EncryptedPrivateKeyInfo_der_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) { if (key_abstract != ((void*)0)) { (ERR_new(), ERR_set_debug("../test/tls-provider.c",2031,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } if ((selection & 0x01) != 0) return key2any_encode(ctx, cout, key, "xorhmacsig", "xorhmacsigPRIVATE KEY", key_to_epki_der_priv_bio, cb, cbarg, prepare_xorx_params, xorx_pki_priv_to_der); (ERR_new(), ERR_set_debug("../test/tls-provider.c",2031,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } static const OSSL_DISPATCH xor_xorhmacsig_to_EncryptedPrivateKeyInfo_der_encoder_functions[] = { { 1, (void (*)(void))key2any_newctx }, { 2, (void (*)(void))key2any_freectx }, { 6, (void (*)(void))key2any_settable_ctx_params }, { 5, (void (*)(void))key2any_set_ctx_params }, { 10, (void (*)(void))xorhmacsig_to_EncryptedPrivateKeyInfo_der_does_selection }, { 20, (void (*)(void))xorhmacsig_to_EncryptedPrivateKeyInfo_der_import_object }, { 21, (void (*)(void))xorhmacsig_to_EncryptedPrivateKeyInfo_der_free_object }, { 11, (void (*)(void))xorhmacsig_to_EncryptedPrivateKeyInfo_der_encode }, { 0, ((void*)0) } };

static OSSL_FUNC_encoder_import_object_fn xorhmacsig_to_EncryptedPrivateKeyInfo_pem_import_object; static OSSL_FUNC_encoder_free_object_fn xorhmacsig_to_EncryptedPrivateKeyInfo_pem_free_object; static OSSL_FUNC_encoder_encode_fn xorhmacsig_to_EncryptedPrivateKeyInfo_pem_encode; static void * xorhmacsig_to_EncryptedPrivateKeyInfo_pem_import_object(void *vctx, int selection, const OSSL_PARAM params[]) { struct key2any_ctx_st *ctx = vctx; return xor_prov_import_key(xor_xorhmacsig_keymgmt_functions, ctx->provctx, selection, params); } static void xorhmacsig_to_EncryptedPrivateKeyInfo_pem_free_object(void *key) { xor_prov_free_key(xor_xorhmacsig_keymgmt_functions, key); } static int xorhmacsig_to_EncryptedPrivateKeyInfo_pem_does_selection(void *ctx, int selection) { return key2any_check_selection(selection, 0x01); } static int xorhmacsig_to_EncryptedPrivateKeyInfo_pem_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) { if (key_abstract != ((void*)0)) { (ERR_new(), ERR_set_debug("../test/tls-provider.c",2032,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } if ((selection & 0x01) != 0) return key2any_encode(ctx, cout, key, "xorhmacsig", "xorhmacsigPRIVATE KEY", key_to_epki_pem_priv_bio, cb, cbarg, prepare_xorx_params, xorx_pki_priv_to_der); (ERR_new(), ERR_set_debug("../test/tls-provider.c",2032,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } static const OSSL_DISPATCH xor_xorhmacsig_to_EncryptedPrivateKeyInfo_pem_encoder_functions[] = { { 1, (void (*)(void))key2any_newctx }, { 2, (void (*)(void))key2any_freectx }, { 6, (void (*)(void))key2any_settable_ctx_params }, { 5, (void (*)(void))key2any_set_ctx_params }, { 10, (void (*)(void))xorhmacsig_to_EncryptedPrivateKeyInfo_pem_does_selection }, { 20, (void (*)(void))xorhmacsig_to_EncryptedPrivateKeyInfo_pem_import_object }, { 21, (void (*)(void))xorhmacsig_to_EncryptedPrivateKeyInfo_pem_free_object }, { 11, (void (*)(void))xorhmacsig_to_EncryptedPrivateKeyInfo_pem_encode }, { 0, ((void*)0) } };

static OSSL_FUNC_encoder_import_object_fn xorhmacsig_to_PrivateKeyInfo_der_import_object; static OSSL_FUNC_encoder_free_object_fn xorhmacsig_to_PrivateKeyInfo_der_free_object; static OSSL_FUNC_encoder_encode_fn xorhmacsig_to_PrivateKeyInfo_der_encode; static void * xorhmacsig_to_PrivateKeyInfo_der_import_object(void *vctx, int selection, const OSSL_PARAM params[]) { struct key2any_ctx_st *ctx = vctx; return xor_prov_import_key(xor_xorhmacsig_keymgmt_functions, ctx->provctx, selection, params); } static void xorhmacsig_to_PrivateKeyInfo_der_free_object(void *key) { xor_prov_free_key(xor_xorhmacsig_keymgmt_functions, key); } static int xorhmacsig_to_PrivateKeyInfo_der_does_selection(void *ctx, int selection) { return key2any_check_selection(selection, 0x01); } static int xorhmacsig_to_PrivateKeyInfo_der_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) { if (key_abstract != ((void*)0)) { (ERR_new(), ERR_set_debug("../test/tls-provider.c",2033,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } if ((selection & 0x01) != 0) return key2any_encode(ctx, cout, key, "xorhmacsig", "xorhmacsigPRIVATE KEY", key_to_pki_der_priv_bio, cb, cbarg, prepare_xorx_params, xorx_pki_priv_to_der); (ERR_new(), ERR_set_debug("../test/tls-provider.c",2033,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } static const OSSL_DISPATCH xor_xorhmacsig_to_PrivateKeyInfo_der_encoder_functions[] = { { 1, (void (*)(void))key2any_newctx }, { 2, (void (*)(void))key2any_freectx }, { 6, (void (*)(void))key2any_settable_ctx_params }, { 5, (void (*)(void))key2any_set_ctx_params }, { 10, (void (*)(void))xorhmacsig_to_PrivateKeyInfo_der_does_selection }, { 20, (void (*)(void))xorhmacsig_to_PrivateKeyInfo_der_import_object }, { 21, (void (*)(void))xorhmacsig_to_PrivateKeyInfo_der_free_object }, { 11, (void (*)(void))xorhmacsig_to_PrivateKeyInfo_der_encode }, { 0, ((void*)0) } };

static OSSL_FUNC_encoder_import_object_fn xorhmacsig_to_PrivateKeyInfo_pem_import_object; static OSSL_FUNC_encoder_free_object_fn xorhmacsig_to_PrivateKeyInfo_pem_free_object; static OSSL_FUNC_encoder_encode_fn xorhmacsig_to_PrivateKeyInfo_pem_encode; static void * xorhmacsig_to_PrivateKeyInfo_pem_import_object(void *vctx, int selection, const OSSL_PARAM params[]) { struct key2any_ctx_st *ctx = vctx; return xor_prov_import_key(xor_xorhmacsig_keymgmt_functions, ctx->provctx, selection, params); } static void xorhmacsig_to_PrivateKeyInfo_pem_free_object(void *key) { xor_prov_free_key(xor_xorhmacsig_keymgmt_functions, key); } static int xorhmacsig_to_PrivateKeyInfo_pem_does_selection(void *ctx, int selection) { return key2any_check_selection(selection, 0x01); } static int xorhmacsig_to_PrivateKeyInfo_pem_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) { if (key_abstract != ((void*)0)) { (ERR_new(), ERR_set_debug("../test/tls-provider.c",2034,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } if ((selection & 0x01) != 0) return key2any_encode(ctx, cout, key, "xorhmacsig", "xorhmacsigPRIVATE KEY", key_to_pki_pem_priv_bio, cb, cbarg, prepare_xorx_params, xorx_pki_priv_to_der); (ERR_new(), ERR_set_debug("../test/tls-provider.c",2034,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } static const OSSL_DISPATCH xor_xorhmacsig_to_PrivateKeyInfo_pem_encoder_functions[] = { { 1, (void (*)(void))key2any_newctx }, { 2, (void (*)(void))key2any_freectx }, { 6, (void (*)(void))key2any_settable_ctx_params }, { 5, (void (*)(void))key2any_set_ctx_params }, { 10, (void (*)(void))xorhmacsig_to_PrivateKeyInfo_pem_does_selection }, { 20, (void (*)(void))xorhmacsig_to_PrivateKeyInfo_pem_import_object }, { 21, (void (*)(void))xorhmacsig_to_PrivateKeyInfo_pem_free_object }, { 11, (void (*)(void))xorhmacsig_to_PrivateKeyInfo_pem_encode }, { 0, ((void*)0) } };

static OSSL_FUNC_encoder_import_object_fn xorhmacsig_to_SubjectPublicKeyInfo_der_import_object; static OSSL_FUNC_encoder_free_object_fn xorhmacsig_to_SubjectPublicKeyInfo_der_free_object; static OSSL_FUNC_encoder_encode_fn xorhmacsig_to_SubjectPublicKeyInfo_der_encode; static void * xorhmacsig_to_SubjectPublicKeyInfo_der_import_object(void *vctx, int selection, const OSSL_PARAM params[]) { struct key2any_ctx_st *ctx = vctx; return xor_prov_import_key(xor_xorhmacsig_keymgmt_functions, ctx->provctx, selection, params); } static void xorhmacsig_to_SubjectPublicKeyInfo_der_free_object(void *key) { xor_prov_free_key(xor_xorhmacsig_keymgmt_functions, key); } static int xorhmacsig_to_SubjectPublicKeyInfo_der_does_selection(void *ctx, int selection) { return key2any_check_selection(selection, 0x02); } static int xorhmacsig_to_SubjectPublicKeyInfo_der_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) { if (key_abstract != ((void*)0)) { (ERR_new(), ERR_set_debug("../test/tls-provider.c",2035,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } if ((selection & 0x02) != 0) return key2any_encode(ctx, cout, key, "xorhmacsig", "xorhmacsigPUBLIC KEY", key_to_spki_der_pub_bio, cb, cbarg, prepare_xorx_params, xorx_spki_pub_to_der); (ERR_new(), ERR_set_debug("../test/tls-provider.c",2035,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } static const OSSL_DISPATCH xor_xorhmacsig_to_SubjectPublicKeyInfo_der_encoder_functions[] = { { 1, (void (*)(void))key2any_newctx }, { 2, (void (*)(void))key2any_freectx }, { 6, (void (*)(void))key2any_settable_ctx_params }, { 5, (void (*)(void))key2any_set_ctx_params }, { 10, (void (*)(void))xorhmacsig_to_SubjectPublicKeyInfo_der_does_selection }, { 20, (void (*)(void))xorhmacsig_to_SubjectPublicKeyInfo_der_import_object }, { 21, (void (*)(void))xorhmacsig_to_SubjectPublicKeyInfo_der_free_object }, { 11, (void (*)(void))xorhmacsig_to_SubjectPublicKeyInfo_der_encode }, { 0, ((void*)0) } };

static OSSL_FUNC_encoder_import_object_fn xorhmacsig_to_SubjectPublicKeyInfo_pem_import_object; static OSSL_FUNC_encoder_free_object_fn xorhmacsig_to_SubjectPublicKeyInfo_pem_free_object; static OSSL_FUNC_encoder_encode_fn xorhmacsig_to_SubjectPublicKeyInfo_pem_encode; static void * xorhmacsig_to_SubjectPublicKeyInfo_pem_import_object(void *vctx, int selection, const OSSL_PARAM params[]) { struct key2any_ctx_st *ctx = vctx; return xor_prov_import_key(xor_xorhmacsig_keymgmt_functions, ctx->provctx, selection, params); } static void xorhmacsig_to_SubjectPublicKeyInfo_pem_free_object(void *key) { xor_prov_free_key(xor_xorhmacsig_keymgmt_functions, key); } static int xorhmacsig_to_SubjectPublicKeyInfo_pem_does_selection(void *ctx, int selection) { return key2any_check_selection(selection, 0x02); } static int xorhmacsig_to_SubjectPublicKeyInfo_pem_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) { if (key_abstract != ((void*)0)) { (ERR_new(), ERR_set_debug("../test/tls-provider.c",2036,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } if ((selection & 0x02) != 0) return key2any_encode(ctx, cout, key, "xorhmacsig", "xorhmacsigPUBLIC KEY", key_to_spki_pem_pub_bio, cb, cbarg, prepare_xorx_params, xorx_spki_pub_to_der); (ERR_new(), ERR_set_debug("../test/tls-provider.c",2036,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } static const OSSL_DISPATCH xor_xorhmacsig_to_SubjectPublicKeyInfo_pem_encoder_functions[] = { { 1, (void (*)(void))key2any_newctx }, { 2, (void (*)(void))key2any_freectx }, { 6, (void (*)(void))key2any_settable_ctx_params }, { 5, (void (*)(void))key2any_set_ctx_params }, { 10, (void (*)(void))xorhmacsig_to_SubjectPublicKeyInfo_pem_does_selection }, { 20, (void (*)(void))xorhmacsig_to_SubjectPublicKeyInfo_pem_import_object }, { 21, (void (*)(void))xorhmacsig_to_SubjectPublicKeyInfo_pem_free_object }, { 11, (void (*)(void))xorhmacsig_to_SubjectPublicKeyInfo_pem_encode }, { 0, ((void*)0) } };

static OSSL_FUNC_encoder_import_object_fn xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_import_object; static OSSL_FUNC_encoder_free_object_fn xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_free_object; static OSSL_FUNC_encoder_encode_fn xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_encode; static void * xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_import_object(void *vctx, int selection, const OSSL_PARAM params[]) { struct key2any_ctx_st *ctx = vctx; return xor_prov_import_key(xor_xorhmacsha2sig_keymgmt_functions, ctx->provctx, selection, params); } static void xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_free_object(void *key) { xor_prov_free_key(xor_xorhmacsha2sig_keymgmt_functions, key); } static int xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_does_selection(void *ctx, int selection) { return key2any_check_selection(selection, 0x01); } static int xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) { if (key_abstract != ((void*)0)) { (ERR_new(), ERR_set_debug("../test/tls-provider.c",2037,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } if ((selection & 0x01) != 0) return key2any_encode(ctx, cout, key, "xorhmacsha2sig", "xorhmacsha2sigPRIVATE KEY", key_to_epki_der_priv_bio, cb, cbarg, prepare_xorx_params, xorx_pki_priv_to_der); (ERR_new(), ERR_set_debug("../test/tls-provider.c",2037,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } static const OSSL_DISPATCH xor_xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_encoder_functions[] = { { 1, (void (*)(void))key2any_newctx }, { 2, (void (*)(void))key2any_freectx }, { 6, (void (*)(void))key2any_settable_ctx_params }, { 5, (void (*)(void))key2any_set_ctx_params }, { 10, (void (*)(void))xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_does_selection }, { 20, (void (*)(void))xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_import_object }, { 21, (void (*)(void))xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_free_object }, { 11, (void (*)(void))xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_encode }, { 0, ((void*)0) } };

static OSSL_FUNC_encoder_import_object_fn xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_import_object; static OSSL_FUNC_encoder_free_object_fn xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_free_object; static OSSL_FUNC_encoder_encode_fn xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_encode; static void * xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_import_object(void *vctx, int selection, const OSSL_PARAM params[]) { struct key2any_ctx_st *ctx = vctx; return xor_prov_import_key(xor_xorhmacsha2sig_keymgmt_functions, ctx->provctx, selection, params); } static void xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_free_object(void *key) { xor_prov_free_key(xor_xorhmacsha2sig_keymgmt_functions, key); } static int xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_does_selection(void *ctx, int selection) { return key2any_check_selection(selection, 0x01); } static int xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) { if (key_abstract != ((void*)0)) { (ERR_new(), ERR_set_debug("../test/tls-provider.c",2038,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } if ((selection & 0x01) != 0) return key2any_encode(ctx, cout, key, "xorhmacsha2sig", "xorhmacsha2sigPRIVATE KEY", key_to_epki_pem_priv_bio, cb, cbarg, prepare_xorx_params, xorx_pki_priv_to_der); (ERR_new(), ERR_set_debug("../test/tls-provider.c",2038,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } static const OSSL_DISPATCH xor_xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_encoder_functions[] = { { 1, (void (*)(void))key2any_newctx }, { 2, (void (*)(void))key2any_freectx }, { 6, (void (*)(void))key2any_settable_ctx_params }, { 5, (void (*)(void))key2any_set_ctx_params }, { 10, (void (*)(void))xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_does_selection }, { 20, (void (*)(void))xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_import_object }, { 21, (void (*)(void))xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_free_object }, { 11, (void (*)(void))xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_encode }, { 0, ((void*)0) } };

static OSSL_FUNC_encoder_import_object_fn xorhmacsha2sig_to_PrivateKeyInfo_der_import_object; static OSSL_FUNC_encoder_free_object_fn xorhmacsha2sig_to_PrivateKeyInfo_der_free_object; static OSSL_FUNC_encoder_encode_fn xorhmacsha2sig_to_PrivateKeyInfo_der_encode; static void * xorhmacsha2sig_to_PrivateKeyInfo_der_import_object(void *vctx, int selection, const OSSL_PARAM params[]) { struct key2any_ctx_st *ctx = vctx; return xor_prov_import_key(xor_xorhmacsha2sig_keymgmt_functions, ctx->provctx, selection, params); } static void xorhmacsha2sig_to_PrivateKeyInfo_der_free_object(void *key) { xor_prov_free_key(xor_xorhmacsha2sig_keymgmt_functions, key); } static int xorhmacsha2sig_to_PrivateKeyInfo_der_does_selection(void *ctx, int selection) { return key2any_check_selection(selection, 0x01); } static int xorhmacsha2sig_to_PrivateKeyInfo_der_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) { if (key_abstract != ((void*)0)) { (ERR_new(), ERR_set_debug("../test/tls-provider.c",2039,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } if ((selection & 0x01) != 0) return key2any_encode(ctx, cout, key, "xorhmacsha2sig", "xorhmacsha2sigPRIVATE KEY", key_to_pki_der_priv_bio, cb, cbarg, prepare_xorx_params, xorx_pki_priv_to_der); (ERR_new(), ERR_set_debug("../test/tls-provider.c",2039,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } static const OSSL_DISPATCH xor_xorhmacsha2sig_to_PrivateKeyInfo_der_encoder_functions[] = { { 1, (void (*)(void))key2any_newctx }, { 2, (void (*)(void))key2any_freectx }, { 6, (void (*)(void))key2any_settable_ctx_params }, { 5, (void (*)(void))key2any_set_ctx_params }, { 10, (void (*)(void))xorhmacsha2sig_to_PrivateKeyInfo_der_does_selection }, { 20, (void (*)(void))xorhmacsha2sig_to_PrivateKeyInfo_der_import_object }, { 21, (void (*)(void))xorhmacsha2sig_to_PrivateKeyInfo_der_free_object }, { 11, (void (*)(void))xorhmacsha2sig_to_PrivateKeyInfo_der_encode }, { 0, ((void*)0) } };

static OSSL_FUNC_encoder_import_object_fn xorhmacsha2sig_to_PrivateKeyInfo_pem_import_object; static OSSL_FUNC_encoder_free_object_fn xorhmacsha2sig_to_PrivateKeyInfo_pem_free_object; static OSSL_FUNC_encoder_encode_fn xorhmacsha2sig_to_PrivateKeyInfo_pem_encode; static void * xorhmacsha2sig_to_PrivateKeyInfo_pem_import_object(void *vctx, int selection, const OSSL_PARAM params[]) { struct key2any_ctx_st *ctx = vctx; return xor_prov_import_key(xor_xorhmacsha2sig_keymgmt_functions, ctx->provctx, selection, params); } static void xorhmacsha2sig_to_PrivateKeyInfo_pem_free_object(void *key) { xor_prov_free_key(xor_xorhmacsha2sig_keymgmt_functions, key); } static int xorhmacsha2sig_to_PrivateKeyInfo_pem_does_selection(void *ctx, int selection) { return key2any_check_selection(selection, 0x01); } static int xorhmacsha2sig_to_PrivateKeyInfo_pem_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) { if (key_abstract != ((void*)0)) { (ERR_new(), ERR_set_debug("../test/tls-provider.c",2040,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } if ((selection & 0x01) != 0) return key2any_encode(ctx, cout, key, "xorhmacsha2sig", "xorhmacsha2sigPRIVATE KEY", key_to_pki_pem_priv_bio, cb, cbarg, prepare_xorx_params, xorx_pki_priv_to_der); (ERR_new(), ERR_set_debug("../test/tls-provider.c",2040,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } static const OSSL_DISPATCH xor_xorhmacsha2sig_to_PrivateKeyInfo_pem_encoder_functions[] = { { 1, (void (*)(void))key2any_newctx }, { 2, (void (*)(void))key2any_freectx }, { 6, (void (*)(void))key2any_settable_ctx_params }, { 5, (void (*)(void))key2any_set_ctx_params }, { 10, (void (*)(void))xorhmacsha2sig_to_PrivateKeyInfo_pem_does_selection }, { 20, (void (*)(void))xorhmacsha2sig_to_PrivateKeyInfo_pem_import_object }, { 21, (void (*)(void))xorhmacsha2sig_to_PrivateKeyInfo_pem_free_object }, { 11, (void (*)(void))xorhmacsha2sig_to_PrivateKeyInfo_pem_encode }, { 0, ((void*)0) } };

static OSSL_FUNC_encoder_import_object_fn xorhmacsha2sig_to_SubjectPublicKeyInfo_der_import_object; static OSSL_FUNC_encoder_free_object_fn xorhmacsha2sig_to_SubjectPublicKeyInfo_der_free_object; static OSSL_FUNC_encoder_encode_fn xorhmacsha2sig_to_SubjectPublicKeyInfo_der_encode; static void * xorhmacsha2sig_to_SubjectPublicKeyInfo_der_import_object(void *vctx, int selection, const OSSL_PARAM params[]) { struct key2any_ctx_st *ctx = vctx; return xor_prov_import_key(xor_xorhmacsha2sig_keymgmt_functions, ctx->provctx, selection, params); } static void xorhmacsha2sig_to_SubjectPublicKeyInfo_der_free_object(void *key) { xor_prov_free_key(xor_xorhmacsha2sig_keymgmt_functions, key); } static int xorhmacsha2sig_to_SubjectPublicKeyInfo_der_does_selection(void *ctx, int selection) { return key2any_check_selection(selection, 0x02); } static int xorhmacsha2sig_to_SubjectPublicKeyInfo_der_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) { if (key_abstract != ((void*)0)) { (ERR_new(), ERR_set_debug("../test/tls-provider.c",2041,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } if ((selection & 0x02) != 0) return key2any_encode(ctx, cout, key, "xorhmacsha2sig", "xorhmacsha2sigPUBLIC KEY", key_to_spki_der_pub_bio, cb, cbarg, prepare_xorx_params, xorx_spki_pub_to_der); (ERR_new(), ERR_set_debug("../test/tls-provider.c",2041,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } static const OSSL_DISPATCH xor_xorhmacsha2sig_to_SubjectPublicKeyInfo_der_encoder_functions[] = { { 1, (void (*)(void))key2any_newctx }, { 2, (void (*)(void))key2any_freectx }, { 6, (void (*)(void))key2any_settable_ctx_params }, { 5, (void (*)(void))key2any_set_ctx_params }, { 10, (void (*)(void))xorhmacsha2sig_to_SubjectPublicKeyInfo_der_does_selection }, { 20, (void (*)(void))xorhmacsha2sig_to_SubjectPublicKeyInfo_der_import_object }, { 21, (void (*)(void))xorhmacsha2sig_to_SubjectPublicKeyInfo_der_free_object }, { 11, (void (*)(void))xorhmacsha2sig_to_SubjectPublicKeyInfo_der_encode }, { 0, ((void*)0) } };

static OSSL_FUNC_encoder_import_object_fn xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_import_object; static OSSL_FUNC_encoder_free_object_fn xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_free_object; static OSSL_FUNC_encoder_encode_fn xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_encode; static void * xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_import_object(void *vctx, int selection, const OSSL_PARAM params[]) { struct key2any_ctx_st *ctx = vctx; return xor_prov_import_key(xor_xorhmacsha2sig_keymgmt_functions, ctx->provctx, selection, params); } static void xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_free_object(void *key) { xor_prov_free_key(xor_xorhmacsha2sig_keymgmt_functions, key); } static int xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_does_selection(void *ctx, int selection) { return key2any_check_selection(selection, 0x02); } static int xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_encode(void *ctx, OSSL_CORE_BIO *cout, const void *key, const OSSL_PARAM key_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) { if (key_abstract != ((void*)0)) { (ERR_new(), ERR_set_debug("../test/tls-provider.c",2042,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } if ((selection & 0x02) != 0) return key2any_encode(ctx, cout, key, "xorhmacsha2sig", "xorhmacsha2sigPUBLIC KEY", key_to_spki_pem_pub_bio, cb, cbarg, prepare_xorx_params, xorx_spki_pub_to_der); (ERR_new(), ERR_set_debug("../test/tls-provider.c",2042,__func__), ERR_set_error)((128),((262|(0x2 << 18L))),((void*)0)); return 0; } static const OSSL_DISPATCH xor_xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_encoder_functions[] = { { 1, (void (*)(void))key2any_newctx }, { 2, (void (*)(void))key2any_freectx }, { 6, (void (*)(void))key2any_settable_ctx_params }, { 5, (void (*)(void))key2any_set_ctx_params }, { 10, (void (*)(void))xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_does_selection }, { 20, (void (*)(void))xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_import_object }, { 21, (void (*)(void))xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_free_object }, { 11, (void (*)(void))xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_encode }, { 0, ((void*)0) } };



static const OSSL_ALGORITHM tls_prov_encoder[] = {

// 2089 "../test/tls-provider.c"

{ "xorhmacsig", "provider=tls-provider,fips=yes,output=der,structure=PrivateKeyInfo", (xor_xorhmacsig_to_PrivateKeyInfo_der_encoder_functions) },

{ "xorhmacsig", "provider=tls-provider,fips=yes,output=pem,structure=PrivateKeyInfo", (xor_xorhmacsig_to_PrivateKeyInfo_pem_encoder_functions) },

{ "xorhmacsig", "provider=tls-provider,fips=yes,output=der,structure=EncryptedPrivateKeyInfo", (xor_xorhmacsig_to_EncryptedPrivateKeyInfo_der_encoder_functions) },

{ "xorhmacsig", "provider=tls-provider,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo", (xor_xorhmacsig_to_EncryptedPrivateKeyInfo_pem_encoder_functions) },

{ "xorhmacsig", "provider=tls-provider,fips=yes,output=der,structure=SubjectPublicKeyInfo", (xor_xorhmacsig_to_SubjectPublicKeyInfo_der_encoder_functions) },

{ "xorhmacsig", "provider=tls-provider,fips=yes,output=pem,structure=SubjectPublicKeyInfo", (xor_xorhmacsig_to_SubjectPublicKeyInfo_pem_encoder_functions) },

{ "xorhmacsha2sig", "provider=tls-provider,fips=yes,output=der,structure=PrivateKeyInfo", (xor_xorhmacsha2sig_to_PrivateKeyInfo_der_encoder_functions) },



{ "xorhmacsha2sig", "provider=tls-provider,fips=yes,output=pem,structure=PrivateKeyInfo", (xor_xorhmacsha2sig_to_PrivateKeyInfo_pem_encoder_functions) },



{ "xorhmacsha2sig", "provider=tls-provider,fips=yes,output=der,structure=EncryptedPrivateKeyInfo", (xor_xorhmacsha2sig_to_EncryptedPrivateKeyInfo_der_encoder_functions) },



{ "xorhmacsha2sig", "provider=tls-provider,fips=yes,output=pem,structure=EncryptedPrivateKeyInfo", (xor_xorhmacsha2sig_to_EncryptedPrivateKeyInfo_pem_encoder_functions) },



{ "xorhmacsha2sig", "provider=tls-provider,fips=yes,output=der,structure=SubjectPublicKeyInfo", (xor_xorhmacsha2sig_to_SubjectPublicKeyInfo_der_encoder_functions) },



{ "xorhmacsha2sig", "provider=tls-provider,fips=yes,output=pem,structure=SubjectPublicKeyInfo", (xor_xorhmacsha2sig_to_SubjectPublicKeyInfo_pem_encoder_functions) },





{ ((void*)0), ((void*)0), ((void*)0) }

};



struct der2key_ctx_st;

typedef int check_key_fn(void *, struct der2key_ctx_st *ctx);

typedef void adjust_key_fn(void *, struct der2key_ctx_st *ctx);

typedef void free_key_fn(void *);

typedef void *d2i_PKCS8_fn(void **, const unsigned char **, long,

struct der2key_ctx_st *);

struct keytype_desc_st {

const char *keytype_name;

const OSSL_DISPATCH *fns;





const char *structure_name;















int evp_type;





int selection_mask;





d2i_of_void *d2i_private_key;

d2i_of_void *d2i_public_key;

d2i_of_void *d2i_key_params;

d2i_PKCS8_fn *d2i_PKCS8;

d2i_of_void *d2i_PUBKEY;













check_key_fn *check_key;











adjust_key_fn *adjust_key;



free_key_fn *free_key;

};















struct X509_pubkey_st {

X509_ALGOR *algor;

ASN1_BIT_STRING *public_key;



EVP_PKEY *pkey;





OSSL_LIB_CTX *libctx;

char *propq;

};



static const ASN1_TEMPLATE X509_PUBKEY_INTERNAL_seq_tt[] = {

{ (0), (0), __builtin_offsetof(X509_PUBKEY, algor), "algor", (X509_ALGOR_it) },

{ (0), (0), __builtin_offsetof(X509_PUBKEY, public_key), "public_key", (ASN1_BIT_STRING_it) }

} ; static const ASN1_ITEM * X509_PUBKEY_INTERNAL_it(void) { static const ASN1_ITEM local_it = { 0x1, 16, X509_PUBKEY_INTERNAL_seq_tt, sizeof(X509_PUBKEY_INTERNAL_seq_tt) / sizeof(ASN1_TEMPLATE), ((void*)0), sizeof(X509_PUBKEY), "X509_PUBKEY" }; return &local_it; }



static X509_PUBKEY *xorx_d2i_X509_PUBKEY_INTERNAL(const unsigned char **pp,

long len, OSSL_LIB_CTX *libctx)

{

X509_PUBKEY *xpub = CRYPTO_zalloc(sizeof(*xpub), "../test/tls-provider.c", 2183);



if (xpub == ((void*)0))

return ((void*)0);

return (X509_PUBKEY *)ASN1_item_d2i_ex((ASN1_VALUE **)&xpub, pp, len,

(X509_PUBKEY_INTERNAL_it()),

libctx, ((void*)0));

}











struct der2key_ctx_st {

PROV_XOR_CTX *provctx;

struct keytype_desc_st *desc;



int selection;



unsigned int flag_fatal : 1;

};



static int xor_read_der(PROV_XOR_CTX *provctx, OSSL_CORE_BIO *cin,

unsigned char **data, long *len)

{

BUF_MEM *mem = ((void*)0);

BIO *in = BIO_new_from_core_bio(provctx->libctx, cin);

int ok = (asn1_d2i_read_bio(in, &mem) >= 0);



if (ok) {

*data = (unsigned char *)mem->data;

*len = (long)mem->length;

CRYPTO_free(mem, "../test/tls-provider.c", 2215);

}

BIO_free(in);

return ok;

}



typedef void *key_from_pkcs8_t(const PKCS8_PRIV_KEY_INFO *p8inf,

OSSL_LIB_CTX *libctx, const char *propq);

static void *xor_der2key_decode_p8(const unsigned char **input_der,

long input_der_len, struct der2key_ctx_st *ctx,

key_from_pkcs8_t *key_from_pkcs8)

{

PKCS8_PRIV_KEY_INFO *p8inf = ((void*)0);

const X509_ALGOR *alg = ((void*)0);

void *key = ((void*)0);



if ((p8inf = d2i_PKCS8_PRIV_KEY_INFO(((void*)0), input_der, input_der_len)) != ((void*)0)

&& PKCS8_pkey_get0(((void*)0), ((void*)0), ((void*)0), &alg, p8inf)

&& OBJ_obj2nid(alg->algorithm) == ctx->desc->evp_type)

key = key_from_pkcs8(p8inf, (((PROV_XOR_CTX *)ctx->provctx)->libctx), ((void*)0));

PKCS8_PRIV_KEY_INFO_free(p8inf);



return key;

}



static XORKEY *xor_d2i_PUBKEY(XORKEY **a,

const unsigned char **pp, long length)

{

XORKEY *key = ((void*)0);

X509_PUBKEY *xpk;



xpk = xorx_d2i_X509_PUBKEY_INTERNAL(pp, length, ((void*)0));



key = xor_key_from_x509pubkey(xpk, ((void*)0), ((void*)0));



if (key == ((void*)0))

goto err_exit;



if (a != ((void*)0)) {

xor_freekey(*a);

*a = key;

}



err_exit:

X509_PUBKEY_free(xpk);

return key;

}









static OSSL_FUNC_decoder_freectx_fn der2key_freectx;

static OSSL_FUNC_decoder_decode_fn xor_der2key_decode;

static OSSL_FUNC_decoder_export_object_fn der2key_export_object;



static struct der2key_ctx_st *

der2key_newctx(void *provctx, struct keytype_desc_st *desc, const char* tls_name)

{

struct der2key_ctx_st *ctx = CRYPTO_zalloc(sizeof(*ctx), "../test/tls-provider.c", 2273);



if (ctx != ((void*)0)) {

ctx->provctx = provctx;

ctx->desc = desc;

if (desc->evp_type == 0) {

ctx->desc->evp_type = OBJ_sn2nid(tls_name);

}

}

return ctx;

}



static void der2key_freectx(void *vctx)

{

struct der2key_ctx_st *ctx = vctx;



CRYPTO_free(ctx, "../test/tls-provider.c", 2289);

}



static int der2key_check_selection(int selection,

const struct keytype_desc_st *desc)

{









int checks[] = {

0x01,

0x02,

( 0x04 | 0x80)

};

size_t i;





if (selection == 0)

return 1;



for (i = 0; i < (sizeof(checks)/sizeof((checks)[0])); i++) {

int check1 = (selection & checks[i]) != 0;

int check2 = (desc->selection_mask & checks[i]) != 0;











if (check1)

return check2;

}





return 0;

}



static int xor_der2key_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,

OSSL_CALLBACK *data_cb, void *data_cbarg,

OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)

{

struct der2key_ctx_st *ctx = vctx;

unsigned char *der = ((void*)0);

const unsigned char *derp;

long der_len = 0;

void *key = ((void*)0);

int ok = 0;



ctx->selection = selection;

// 2346 "../test/tls-provider.c"

if (selection == 0)

selection = ctx->desc->selection_mask;

if ((selection & ctx->desc->selection_mask) == 0) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",2349,__func__), ERR_set_error)((57),((262|(0x2 << 18L))),((void*)0));

return 0;

}



ok = xor_read_der(ctx->provctx, cin, &der, &der_len);

if (!ok)

goto next;



ok = 0;



if ((selection & 0x01) != 0) {

derp = der;

if (ctx->desc->d2i_PKCS8 != ((void*)0)) {

key = ctx->desc->d2i_PKCS8(((void*)0), &derp, der_len, ctx);

if (ctx->flag_fatal)

goto end;

} else if (ctx->desc->d2i_private_key != ((void*)0)) {

key = ctx->desc->d2i_private_key(((void*)0), &derp, der_len);

}

if (key == ((void*)0) && ctx->selection != 0)

goto next;

}

if (key == ((void*)0) && (selection & 0x02) != 0) {

derp = der;

if (ctx->desc->d2i_PUBKEY != ((void*)0))

key = ctx->desc->d2i_PUBKEY(((void*)0), &derp, der_len);

else

key = ctx->desc->d2i_public_key(((void*)0), &derp, der_len);

if (key == ((void*)0) && ctx->selection != 0)

goto next;

}

if (key == ((void*)0) && (selection & ( 0x04 | 0x80)) != 0) {

derp = der;

if (ctx->desc->d2i_key_params != ((void*)0))

key = ctx->desc->d2i_key_params(((void*)0), &derp, der_len);

if (key == ((void*)0) && ctx->selection != 0)

goto next;

}

// 2395 "../test/tls-provider.c"

if (key != ((void*)0)

&& ctx->desc->check_key != ((void*)0)

&& !ctx->desc->check_key(key, ctx)) {

ctx->desc->free_key(key);

key = ((void*)0);

}



if (key != ((void*)0) && ctx->desc->adjust_key != ((void*)0))

ctx->desc->adjust_key(key, ctx);



next:









ok = 1;













CRYPTO_free(der, "../test/tls-provider.c", 2417);

der = ((void*)0);



if (key != ((void*)0)) {

OSSL_PARAM params[4];

int object_type = 2;



params[0] =

OSSL_PARAM_construct_int("type", &object_type);

params[1] =

OSSL_PARAM_construct_utf8_string("data-type",

(char *)ctx->desc->keytype_name,

0);



params[2] =

OSSL_PARAM_construct_octet_string("reference",

&key, sizeof(key));

params[3] = OSSL_PARAM_construct_end();



ok = data_cb(params, data_cbarg);

}



end:

ctx->desc->free_key(key);

CRYPTO_free(der, "../test/tls-provider.c", 2441);



return ok;

}



static int der2key_export_object(void *vctx,

const void *reference, size_t reference_sz,

OSSL_CALLBACK *export_cb, void *export_cbarg)

{

struct der2key_ctx_st *ctx = vctx;

OSSL_FUNC_keymgmt_export_fn *export =

xor_prov_get_keymgmt_export(ctx->desc->fns);

void *keydata;



if (reference_sz == sizeof(keydata) && export != ((void*)0)) {



keydata = *(void **)reference;



return export(keydata, ctx->selection, export_cb, export_cbarg);

}

return 0;

}







static void *xorx_d2i_PKCS8(void **key, const unsigned char **der, long der_len,

struct der2key_ctx_st *ctx)

{

return xor_der2key_decode_p8(der, der_len, ctx,

(key_from_pkcs8_t *)xor_key_from_pkcs8);

}



static void xorx_key_adjust(void *key, struct der2key_ctx_st *ctx)

{

}

// 2552 "../test/tls-provider.c"

static struct keytype_desc_st PrivateKeyInfo_xorhmacsig_desc = { "xorhmacsig", xor_xorhmacsig_keymgmt_functions, "PrivateKeyInfo", 0, ( 0x01 ), ((void*)0), ((void*)0), ((void*)0), xorx_d2i_PKCS8, ((void*)0), ((void*)0), xorx_key_adjust, (free_key_fn *)xor_freekey }; static OSSL_FUNC_decoder_newctx_fn PrivateKeyInfo_der2xorhmacsig_newctx; static void *PrivateKeyInfo_der2xorhmacsig_newctx(void *provctx) { return der2key_newctx(provctx, &PrivateKeyInfo_xorhmacsig_desc, "xorhmacsig" ); } static int PrivateKeyInfo_der2xorhmacsig_does_selection(void *provctx, int selection) { return der2key_check_selection(selection, &PrivateKeyInfo_xorhmacsig_desc); } static const OSSL_DISPATCH xor_PrivateKeyInfo_der_to_xorhmacsig_decoder_functions[] = { { 1, (void (*)(void))PrivateKeyInfo_der2xorhmacsig_newctx }, { 2, (void (*)(void))der2key_freectx }, { 10, (void (*)(void))PrivateKeyInfo_der2xorhmacsig_does_selection }, { 11, (void (*)(void))xor_der2key_decode }, { 20, (void (*)(void))der2key_export_object }, { 0, ((void*)0) } };

static struct keytype_desc_st SubjectPublicKeyInfo_xorhmacsig_desc = { "xorhmacsig", xor_xorhmacsig_keymgmt_functions, "SubjectPublicKeyInfo", 0, ( 0x02 ), ((void*)0), ((void*)0), ((void*)0), ((void*)0), (d2i_of_void *)xor_d2i_PUBKEY, ((void*)0), xorx_key_adjust, (free_key_fn *)xor_freekey }; static OSSL_FUNC_decoder_newctx_fn SubjectPublicKeyInfo_der2xorhmacsig_newctx; static void *SubjectPublicKeyInfo_der2xorhmacsig_newctx(void *provctx) { return der2key_newctx(provctx, &SubjectPublicKeyInfo_xorhmacsig_desc, "xorhmacsig" ); } static int SubjectPublicKeyInfo_der2xorhmacsig_does_selection(void *provctx, int selection) { return der2key_check_selection(selection, &SubjectPublicKeyInfo_xorhmacsig_desc); } static const OSSL_DISPATCH xor_SubjectPublicKeyInfo_der_to_xorhmacsig_decoder_functions[] = { { 1, (void (*)(void))SubjectPublicKeyInfo_der2xorhmacsig_newctx }, { 2, (void (*)(void))der2key_freectx }, { 10, (void (*)(void))SubjectPublicKeyInfo_der2xorhmacsig_does_selection }, { 11, (void (*)(void))xor_der2key_decode }, { 20, (void (*)(void))der2key_export_object }, { 0, ((void*)0) } };

static struct keytype_desc_st PrivateKeyInfo_xorhmacsha2sig_desc = { "xorhmacsha2sig", xor_xorhmacsha2sig_keymgmt_functions, "PrivateKeyInfo", 0, ( 0x01 ), ((void*)0), ((void*)0), ((void*)0), xorx_d2i_PKCS8, ((void*)0), ((void*)0), xorx_key_adjust, (free_key_fn *)xor_freekey }; static OSSL_FUNC_decoder_newctx_fn PrivateKeyInfo_der2xorhmacsha2sig_newctx; static void *PrivateKeyInfo_der2xorhmacsha2sig_newctx(void *provctx) { return der2key_newctx(provctx, &PrivateKeyInfo_xorhmacsha2sig_desc, "xorhmacsha2sig" ); } static int PrivateKeyInfo_der2xorhmacsha2sig_does_selection(void *provctx, int selection) { return der2key_check_selection(selection, &PrivateKeyInfo_xorhmacsha2sig_desc); } static const OSSL_DISPATCH xor_PrivateKeyInfo_der_to_xorhmacsha2sig_decoder_functions[] = { { 1, (void (*)(void))PrivateKeyInfo_der2xorhmacsha2sig_newctx }, { 2, (void (*)(void))der2key_freectx }, { 10, (void (*)(void))PrivateKeyInfo_der2xorhmacsha2sig_does_selection }, { 11, (void (*)(void))xor_der2key_decode }, { 20, (void (*)(void))der2key_export_object }, { 0, ((void*)0) } };

static struct keytype_desc_st SubjectPublicKeyInfo_xorhmacsha2sig_desc = { "xorhmacsha2sig", xor_xorhmacsha2sig_keymgmt_functions, "SubjectPublicKeyInfo", 0, ( 0x02 ), ((void*)0), ((void*)0), ((void*)0), ((void*)0), (d2i_of_void *)xor_d2i_PUBKEY, ((void*)0), xorx_key_adjust, (free_key_fn *)xor_freekey }; static OSSL_FUNC_decoder_newctx_fn SubjectPublicKeyInfo_der2xorhmacsha2sig_newctx; static void *SubjectPublicKeyInfo_der2xorhmacsha2sig_newctx(void *provctx) { return der2key_newctx(provctx, &SubjectPublicKeyInfo_xorhmacsha2sig_desc, "xorhmacsha2sig" ); } static int SubjectPublicKeyInfo_der2xorhmacsha2sig_does_selection(void *provctx, int selection) { return der2key_check_selection(selection, &SubjectPublicKeyInfo_xorhmacsha2sig_desc); } static const OSSL_DISPATCH xor_SubjectPublicKeyInfo_der_to_xorhmacsha2sig_decoder_functions[] = { { 1, (void (*)(void))SubjectPublicKeyInfo_der2xorhmacsha2sig_newctx }, { 2, (void (*)(void))der2key_freectx }, { 10, (void (*)(void))SubjectPublicKeyInfo_der2xorhmacsha2sig_does_selection }, { 11, (void (*)(void))xor_der2key_decode }, { 20, (void (*)(void))der2key_export_object }, { 0, ((void*)0) } };



static const OSSL_ALGORITHM tls_prov_decoder[] = {

// 2578 "../test/tls-provider.c"

{ "xorhmacsig", "provider=tls-provider,fips=yes,input=der,structure=PrivateKeyInfo", (xor_PrivateKeyInfo_der_to_xorhmacsig_decoder_functions) },

{ "xorhmacsig", "provider=tls-provider,fips=yes,input=der,structure=SubjectPublicKeyInfo", (xor_SubjectPublicKeyInfo_der_to_xorhmacsig_decoder_functions) },

{ "xorhmacsha2sig", "provider=tls-provider,fips=yes,input=der,structure=PrivateKeyInfo", (xor_PrivateKeyInfo_der_to_xorhmacsha2sig_decoder_functions) },

{ "xorhmacsha2sig", "provider=tls-provider,fips=yes,input=der,structure=SubjectPublicKeyInfo", (xor_SubjectPublicKeyInfo_der_to_xorhmacsha2sig_decoder_functions) },



{ ((void*)0), ((void*)0), ((void*)0) }

};









static OSSL_FUNC_signature_newctx_fn xor_sig_newctx;

static OSSL_FUNC_signature_sign_init_fn xor_sig_sign_init;

static OSSL_FUNC_signature_verify_init_fn xor_sig_verify_init;

static OSSL_FUNC_signature_sign_fn xor_sig_sign;

static OSSL_FUNC_signature_verify_fn xor_sig_verify;

static OSSL_FUNC_signature_digest_sign_init_fn xor_sig_digest_sign_init;

static OSSL_FUNC_signature_digest_sign_update_fn xor_sig_digest_signverify_update;

static OSSL_FUNC_signature_digest_sign_final_fn xor_sig_digest_sign_final;

static OSSL_FUNC_signature_digest_verify_init_fn xor_sig_digest_verify_init;

static OSSL_FUNC_signature_digest_verify_update_fn xor_sig_digest_signverify_update;

static OSSL_FUNC_signature_digest_verify_final_fn xor_sig_digest_verify_final;

static OSSL_FUNC_signature_freectx_fn xor_sig_freectx;

static OSSL_FUNC_signature_dupctx_fn xor_sig_dupctx;

static OSSL_FUNC_signature_get_ctx_params_fn xor_sig_get_ctx_params;

static OSSL_FUNC_signature_gettable_ctx_params_fn xor_sig_gettable_ctx_params;

static OSSL_FUNC_signature_set_ctx_params_fn xor_sig_set_ctx_params;

static OSSL_FUNC_signature_settable_ctx_params_fn xor_sig_settable_ctx_params;

static OSSL_FUNC_signature_get_ctx_md_params_fn xor_sig_get_ctx_md_params;

static OSSL_FUNC_signature_gettable_ctx_md_params_fn xor_sig_gettable_ctx_md_params;

static OSSL_FUNC_signature_set_ctx_md_params_fn xor_sig_set_ctx_md_params;

static OSSL_FUNC_signature_settable_ctx_md_params_fn xor_sig_settable_ctx_md_params;



static int xor_get_aid(unsigned char** oidbuf, const char *tls_name) {

X509_ALGOR *algor = X509_ALGOR_new();

int aidlen = 0;



X509_ALGOR_set0(algor, OBJ_txt2obj(tls_name, 0), -1, ((void*)0));



aidlen = i2d_X509_ALGOR(algor, oidbuf);

X509_ALGOR_free(algor);

return(aidlen);

}









typedef struct {

OSSL_LIB_CTX *libctx;

char *propq;

XORKEY *sig;















unsigned int flag_allow_md : 1;



char mdname[50];





unsigned char *aid;

size_t aid_len;





EVP_MD *md;

EVP_MD_CTX *mdctx;

int operation;

} PROV_XORSIG_CTX;



static void *xor_sig_newctx(void *provctx, const char *propq)

{

PROV_XORSIG_CTX *pxor_sigctx;



pxor_sigctx = CRYPTO_zalloc(sizeof(PROV_XORSIG_CTX), "../test/tls-provider.c", 2654);

if (pxor_sigctx == ((void*)0))

return ((void*)0);



pxor_sigctx->libctx = ((PROV_XOR_CTX*)provctx)->libctx;

pxor_sigctx->flag_allow_md = 0;

if (propq != ((void*)0) && (pxor_sigctx->propq = CRYPTO_strdup(propq, "../test/tls-provider.c", 2660)) == ((void*)0)) {

CRYPTO_free(pxor_sigctx, "../test/tls-provider.c", 2661);

pxor_sigctx = ((void*)0);

(ERR_new(), ERR_set_debug("../test/tls-provider.c",2663,__func__), ERR_set_error)((128),((256|((0x1 << 18L)|(0x2 << 18L)))),((void*)0));

}

return pxor_sigctx;

}



static int xor_sig_setup_md(PROV_XORSIG_CTX *ctx,

const char *mdname, const char *mdprops)

{

EVP_MD *md;



if (mdprops == ((void*)0))

mdprops = ctx->propq;



md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);



if ((md == ((void*)0)) || (EVP_MD_get_type(md)==0)) {

if (md == ((void*)0))

(ERR_new(), ERR_set_debug("../test/tls-provider.c",2680,__func__), ERR_set_error)(128, 1,

"%s could not be fetched", mdname);

EVP_MD_free(md);

return 0;

}



EVP_MD_CTX_free(ctx->mdctx);

ctx->mdctx = ((void*)0);

EVP_MD_free(ctx->md);

ctx->md = ((void*)0);



CRYPTO_free(ctx->aid, "../test/tls-provider.c", 2691);

ctx->aid = ((void*)0);

ctx->aid_len = xor_get_aid(&(ctx->aid), ctx->sig->tls_name);

if (ctx->aid_len <= 0) {

EVP_MD_free(md);

return 0;

}



ctx->mdctx = ((void*)0);

ctx->md = md;

OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));

return 1;

}



static int xor_sig_signverify_init(void *vpxor_sigctx, void *vxorsig,

int operation)

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;



if (pxor_sigctx == ((void*)0) || vxorsig == ((void*)0))

return 0;

xor_freekey(pxor_sigctx->sig);

if (!xor_key_up_ref(vxorsig))

return 0;

pxor_sigctx->sig = vxorsig;

pxor_sigctx->operation = operation;

if ((operation==(1<<4) && pxor_sigctx->sig == ((void*)0))

|| (operation==(1<<5) && pxor_sigctx->sig == ((void*)0))) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",2719,__func__), ERR_set_error)((128),(3),((void*)0));

return 0;

}

return 1;

}



static int xor_sig_sign_init(void *vpxor_sigctx, void *vxorsig,

const OSSL_PARAM params[])

{

return xor_sig_signverify_init(vpxor_sigctx, vxorsig, (1<<4));

}



static int xor_sig_verify_init(void *vpxor_sigctx, void *vxorsig,

const OSSL_PARAM params[])

{

return xor_sig_signverify_init(vpxor_sigctx, vxorsig, (1<<5));

}



static int xor_sig_sign(void *vpxor_sigctx, unsigned char *sig, size_t *siglen,

size_t sigsize, const unsigned char *tbs, size_t tbslen)

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;

XORKEY *xorkey = pxor_sigctx->sig;



size_t max_sig_len = 64;

size_t xor_sig_len = 0;

int rv = 0;



if (xorkey == ((void*)0) || !xorkey->hasprivkey) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",2748,__func__), ERR_set_error)((128),(10),((void*)0));

return rv;

}



if (sig == ((void*)0)) {

*siglen = max_sig_len;

return 1;

}

if (*siglen < max_sig_len) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",2757,__func__), ERR_set_error)((128),(11),((void*)0));

return rv;

}











if (!EVP_Q_mac(pxor_sigctx->libctx, "HMAC", ((void*)0), "sha1", ((void*)0),

xorkey->privkey, 32, tbs, tbslen,

&sig[0], 64, &xor_sig_len)) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",2768,__func__), ERR_set_error)((128),(12),((void*)0));

goto endsign;

}



*siglen = xor_sig_len;

rv = 1;



endsign:

return rv;

}



static int xor_sig_verify(void *vpxor_sigctx,

const unsigned char *sig, size_t siglen,

const unsigned char *tbs, size_t tbslen)

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;

XORKEY *xorkey = pxor_sigctx->sig;

unsigned char resignature[64];

size_t resiglen;

int i;



if (xorkey == ((void*)0) || sig == ((void*)0) || tbs == ((void*)0)) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",2790,__func__), ERR_set_error)((128),(13),((void*)0));

return 0;

}













for (i = 0; i < 32; i++)

xorkey->privkey[i] = xorkey->pubkey[i] ^ private_constant[i];





if (!EVP_Q_mac(pxor_sigctx->libctx, "HMAC", ((void*)0), "sha1", ((void*)0),

xorkey->privkey, 32, tbs, tbslen,

&resignature[0], 64, &resiglen)) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",2806,__func__), ERR_set_error)((128),(14),((void*)0));

return 0;

}





if (siglen != resiglen || memcmp(resignature, sig, siglen) != 0) {

(ERR_new(), ERR_set_debug("../test/tls-provider.c",2812,__func__), ERR_set_error)((128),(14),((void*)0));

return 0;

}

return 1;

}



static int xor_sig_digest_signverify_init(void *vpxor_sigctx, const char *mdname,

void *vxorsig, int operation)

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;

char *rmdname = (char *)mdname;



if (rmdname == ((void*)0))

rmdname = "sha256";



pxor_sigctx->flag_allow_md = 0;

if (!xor_sig_signverify_init(vpxor_sigctx, vxorsig, operation))

return 0;



if (!xor_sig_setup_md(pxor_sigctx, rmdname, ((void*)0)))

return 0;



pxor_sigctx->mdctx = EVP_MD_CTX_new();

if (pxor_sigctx->mdctx == ((void*)0))

goto error;



if (!EVP_DigestInit_ex(pxor_sigctx->mdctx, pxor_sigctx->md, ((void*)0)))

goto error;



return 1;



error:

EVP_MD_CTX_free(pxor_sigctx->mdctx);

EVP_MD_free(pxor_sigctx->md);

pxor_sigctx->mdctx = ((void*)0);

pxor_sigctx->md = ((void*)0);

return 0;

}



static int xor_sig_digest_sign_init(void *vpxor_sigctx, const char *mdname,

void *vxorsig, const OSSL_PARAM params[])

{

return xor_sig_digest_signverify_init(vpxor_sigctx, mdname, vxorsig,

(1<<4));

}



static int xor_sig_digest_verify_init(void *vpxor_sigctx, const char *mdname, void *vxorsig, const OSSL_PARAM params[])

{

return xor_sig_digest_signverify_init(vpxor_sigctx, mdname,

vxorsig, (1<<5));

}



int xor_sig_digest_signverify_update(void *vpxor_sigctx,

const unsigned char *data,

size_t datalen)

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;



if (pxor_sigctx == ((void*)0) || pxor_sigctx->mdctx == ((void*)0))

return 0;



return EVP_DigestUpdate(pxor_sigctx->mdctx, data, datalen);

}



int xor_sig_digest_sign_final(void *vpxor_sigctx,

unsigned char *sig, size_t *siglen,

size_t sigsize)

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;

unsigned char digest[64];

unsigned int dlen = 0;



if (sig != ((void*)0)) {

if (pxor_sigctx == ((void*)0) || pxor_sigctx->mdctx == ((void*)0))

return 0;



if (!EVP_DigestFinal_ex(pxor_sigctx->mdctx, digest, &dlen))

return 0;



pxor_sigctx->flag_allow_md = 1;

}



return xor_sig_sign(vpxor_sigctx, sig, siglen, sigsize, digest, (size_t)dlen);



}



int xor_sig_digest_verify_final(void *vpxor_sigctx, const unsigned char *sig,

size_t siglen)

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;

unsigned char digest[64];

unsigned int dlen = 0;



if (pxor_sigctx == ((void*)0) || pxor_sigctx->mdctx == ((void*)0))

return 0;



if (!EVP_DigestFinal_ex(pxor_sigctx->mdctx, digest, &dlen))

return 0;



pxor_sigctx->flag_allow_md = 1;



return xor_sig_verify(vpxor_sigctx, sig, siglen, digest, (size_t)dlen);

}



static void xor_sig_freectx(void *vpxor_sigctx)

{

PROV_XORSIG_CTX *ctx = (PROV_XORSIG_CTX *)vpxor_sigctx;



CRYPTO_free(ctx->propq, "../test/tls-provider.c", 2920);

EVP_MD_CTX_free(ctx->mdctx);

EVP_MD_free(ctx->md);

ctx->propq = ((void*)0);

ctx->mdctx = ((void*)0);

ctx->md = ((void*)0);

xor_freekey(ctx->sig);

ctx->sig = ((void*)0);

CRYPTO_free(ctx->aid, "../test/tls-provider.c", 2928);

CRYPTO_free(ctx, "../test/tls-provider.c", 2929);

}



static void *xor_sig_dupctx(void *vpxor_sigctx)

{

PROV_XORSIG_CTX *srcctx = (PROV_XORSIG_CTX *)vpxor_sigctx;

PROV_XORSIG_CTX *dstctx;



dstctx = CRYPTO_zalloc(sizeof(*srcctx), "../test/tls-provider.c", 2937);

if (dstctx == ((void*)0))

return ((void*)0);



*dstctx = *srcctx;

dstctx->sig = ((void*)0);

dstctx->md = ((void*)0);

dstctx->mdctx = ((void*)0);

dstctx->aid = ((void*)0);



if ((srcctx->sig != ((void*)0)) && !xor_key_up_ref(srcctx->sig))

goto err;

dstctx->sig = srcctx->sig;



if (srcctx->md != ((void*)0) && !EVP_MD_up_ref(srcctx->md))

goto err;

dstctx->md = srcctx->md;



if (srcctx->mdctx != ((void*)0)) {

dstctx->mdctx = EVP_MD_CTX_new();

if (dstctx->mdctx == ((void*)0)

|| !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))

goto err;

}



return dstctx;

err:

xor_sig_freectx(dstctx);

return ((void*)0);

}



static int xor_sig_get_ctx_params(void *vpxor_sigctx, OSSL_PARAM *params)

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;

OSSL_PARAM *p;



if (pxor_sigctx == ((void*)0) || params == ((void*)0))

return 0;



p = OSSL_PARAM_locate(params, "algorithm-id");



if (pxor_sigctx->aid == ((void*)0))

pxor_sigctx->aid_len = xor_get_aid(&(pxor_sigctx->aid), pxor_sigctx->sig->tls_name);



if (p != ((void*)0)

&& !OSSL_PARAM_set_octet_string(p, pxor_sigctx->aid, pxor_sigctx->aid_len))

return 0;



p = OSSL_PARAM_locate(params, "digest");

if (p != ((void*)0) && !OSSL_PARAM_set_utf8_string(p, pxor_sigctx->mdname))

return 0;



return 1;

}



static const OSSL_PARAM known_gettable_ctx_params[] = {

{ (("algorithm-id")), (5), ((((void*)0))), (0), ((size_t)-1) },

{ (("digest")), (4), ((((void*)0))), (0), ((size_t)-1) },

{ ((void*)0), 0, ((void*)0), 0, 0 }

};



static const OSSL_PARAM *xor_sig_gettable_ctx_params( void *vpxor_sigctx,  void *vctx)

{

return known_gettable_ctx_params;

}



static int xor_sig_set_ctx_params(void *vpxor_sigctx, const OSSL_PARAM params[])

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;

const OSSL_PARAM *p;



if (pxor_sigctx == ((void*)0) || params == ((void*)0))

return 0;



p = OSSL_PARAM_locate_const(params, "digest");



if (p != ((void*)0) && !pxor_sigctx->flag_allow_md)

return 0;

if (p != ((void*)0)) {

char mdname[50] = "", *pmdname = mdname;

char mdprops[256] = "", *pmdprops = mdprops;

const OSSL_PARAM *propsp =

OSSL_PARAM_locate_const(params,

"properties");



if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))

return 0;

if (propsp != ((void*)0)

&& !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))

return 0;

if (!xor_sig_setup_md(pxor_sigctx, mdname, mdprops))

return 0;

}



return 1;

}



static const OSSL_PARAM known_settable_ctx_params[] = {

{ (("digest")), (4), ((((void*)0))), (0), ((size_t)-1) },

{ (("properties")), (4), ((((void*)0))), (0), ((size_t)-1) },

{ ((void*)0), 0, ((void*)0), 0, 0 }

};



static const OSSL_PARAM *xor_sig_settable_ctx_params( void *vpsm2ctx,

void *provctx)

{

return known_settable_ctx_params;

}



static int xor_sig_get_ctx_md_params(void *vpxor_sigctx, OSSL_PARAM *params)

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;



if (pxor_sigctx->mdctx == ((void*)0))

return 0;



return EVP_MD_CTX_get_params(pxor_sigctx->mdctx, params);

}



static const OSSL_PARAM *xor_sig_gettable_ctx_md_params(void *vpxor_sigctx)

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;



if (pxor_sigctx->md == ((void*)0))

return 0;



return EVP_MD_gettable_ctx_params(pxor_sigctx->md);

}



static int xor_sig_set_ctx_md_params(void *vpxor_sigctx, const OSSL_PARAM params[])

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;



if (pxor_sigctx->mdctx == ((void*)0))

return 0;



return EVP_MD_CTX_set_params(pxor_sigctx->mdctx, params);

}



static const OSSL_PARAM *xor_sig_settable_ctx_md_params(void *vpxor_sigctx)

{

PROV_XORSIG_CTX *pxor_sigctx = (PROV_XORSIG_CTX *)vpxor_sigctx;



if (pxor_sigctx->md == ((void*)0))

return 0;



return EVP_MD_settable_ctx_params(pxor_sigctx->md);

}



static const OSSL_DISPATCH xor_signature_functions[] = {

{ 1, (void (*)(void))xor_sig_newctx },

{ 2, (void (*)(void))xor_sig_sign_init },

{ 3, (void (*)(void))xor_sig_sign },

{ 4, (void (*)(void))xor_sig_verify_init },

{ 5, (void (*)(void))xor_sig_verify },

{ 8,

(void (*)(void))xor_sig_digest_sign_init },

{ 9,

(void (*)(void))xor_sig_digest_signverify_update },

{ 10,

(void (*)(void))xor_sig_digest_sign_final },

{ 12,

(void (*)(void))xor_sig_digest_verify_init },

{ 13,

(void (*)(void))xor_sig_digest_signverify_update },

{ 14,

(void (*)(void))xor_sig_digest_verify_final },

{ 16, (void (*)(void))xor_sig_freectx },

{ 17, (void (*)(void))xor_sig_dupctx },

{ 18, (void (*)(void))xor_sig_get_ctx_params },

{ 19,

(void (*)(void))xor_sig_gettable_ctx_params },

{ 20, (void (*)(void))xor_sig_set_ctx_params },

{ 21,

(void (*)(void))xor_sig_settable_ctx_params },

{ 22,

(void (*)(void))xor_sig_get_ctx_md_params },

{ 23,

(void (*)(void))xor_sig_gettable_ctx_md_params },

{ 24,

(void (*)(void))xor_sig_set_ctx_md_params },

{ 25,

(void (*)(void))xor_sig_settable_ctx_md_params },

{ 0, ((void*)0) }

};



static const OSSL_ALGORITHM tls_prov_signature[] = {









{ "xorhmacsig", "provider=tls-provider,fips=yes",

xor_signature_functions },

{ "xorhmacsha2sig", "provider=tls-provider,fips=yes",

xor_signature_functions },

{ "xorhmacsig12", "provider=tls-provider,fips=yes",

xor_signature_functions },

{ ((void*)0), ((void*)0), ((void*)0) }

};





static const OSSL_ALGORITHM *tls_prov_query(void *provctx, int operation_id,

int *no_cache)

{

*no_cache = 0;

switch (operation_id) {

case 10:

return tls_prov_keymgmt;

case 11:

return tls_prov_keyexch;

case 14:

return tls_prov_kem;

case 20:

return tls_prov_encoder;

case 21:

return tls_prov_decoder;

case 12:

return tls_prov_signature;

}

return ((void*)0);

}



static void tls_prov_teardown(void *provctx)

{

int i;

PROV_XOR_CTX *pctx = (PROV_XOR_CTX*)provctx;



OSSL_LIB_CTX_free(pctx->libctx);



for (i = 0; i < 50; i++) {

CRYPTO_free(dummy_group_names[i], "../test/tls-provider.c", 3167);

dummy_group_names[i] = ((void*)0);

}

CRYPTO_free(pctx, "../test/tls-provider.c", 3170);

}





static const OSSL_DISPATCH tls_prov_dispatch_table[] = {

{ 1024, (void (*)(void))tls_prov_teardown },

{ 1027, (void (*)(void))tls_prov_query },

{ 1030, (void (*)(void))tls_prov_get_capabilities },

{ 0, ((void*)0) }

};



static

unsigned int randomize_tls_alg_id(OSSL_LIB_CTX *libctx)

{









unsigned int id;

static unsigned int mem[10] = { 0 };

static int in_mem = 0;

int i;



retry:

if (RAND_bytes_ex(libctx, (unsigned char *)&id, sizeof(id), 0) <= 0)

return 0;











id %= 65279 - 50 - 65024;

id += 65024;





for (i = 0; i < in_mem; i++)

if (mem[i] == id)

goto retry;





mem[in_mem++] = id;



return id;

}



int tls_provider_init(const OSSL_CORE_HANDLE *handle,

const OSSL_DISPATCH *in,

const OSSL_DISPATCH **out,

void **provctx)

{

OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);

OSSL_FUNC_core_obj_create_fn *c_obj_create= ((void*)0);

OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid= ((void*)0);

PROV_XOR_CTX *prov_ctx = xor_newprovctx(libctx);



if (libctx == ((void*)0) || prov_ctx == ((void*)0))


// clang-format off

/*target_line*/return 0;

// clang-format on



return 0;

}
// Fuzzing wrapper body



ssize_t       fuzz_len;
unsigned char fuzz_buf[1024000];
#define __AFL_FUZZ_TESTCASE_LEN fuzz_len
#define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
#define __AFL_FUZZ_INIT() void sync(void);
#define __AFL_LOOP(x)     ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
#define __AFL_INIT() sync()
                
__AFL_FUZZ_INIT();
main() {
// anything else here, e.g. command line arguments, initialization, etc.
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
unsigned char *Fuzz_Data = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT and before __AFL_LOOP!
while (__AFL_LOOP(10000)) {
    int Fuzz_Size = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a call!

    // check for a required/useful minimum input length

    if (Fuzz_Size < 6
 + sizeof(char)+sizeof(OSSL_DISPATCH )+sizeof(int*)+sizeof(OSSL_DISPATCH )+sizeof(int*)+sizeof(char)
) continue;

    size_t dyn_size = (int) ((Fuzz_Size - (6
 + sizeof(char)+sizeof(OSSL_DISPATCH )+sizeof(int*)+sizeof(OSSL_DISPATCH )+sizeof(int*)+sizeof(char)
))/6);

    uint8_t * pos = Fuzz_Data;

    //GEN_STRUCT

    
 	OSSL_CORE_HANDLE  *handle;
    
	handle= malloc(sizeof(char)*(1 + (dyn_size/sizeof(char))));
    
 	memset(handle,0, sizeof(char) * (1 + (dyn_size/sizeof(char))));
    
	memcpy(handle, pos, sizeof(char)* ((1 + (dyn_size/sizeof(char))) - 1));
    
	pos += sizeof(char)* ((1 + (dyn_size/sizeof(char))) - 1);
    //GEN_STRUCT

    
 	OSSL_DISPATCH  *in;
    
	in= malloc(sizeof(OSSL_DISPATCH )*(1 + (dyn_size/sizeof(OSSL_DISPATCH ))));
    
 	memset(in,0, sizeof(OSSL_DISPATCH ) * (1 + (dyn_size/sizeof(OSSL_DISPATCH ))));
    
	memcpy(in, pos, sizeof(OSSL_DISPATCH )* ((1 + (dyn_size/sizeof(OSSL_DISPATCH ))) - 1));
    
	pos += sizeof(OSSL_DISPATCH )* ((1 + (dyn_size/sizeof(OSSL_DISPATCH ))) - 1);
    //GEN_STRUCT

    
 	OSSL_DISPATCH  **out;
    
 	out = malloc(sizeof(int*)*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))));
    
 	memset(out,0, sizeof(int*) * (1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))));
    
 	for ( int index_a= 0; index_a < (1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))) - 1; index_a++ )
 	{

    
	out[index_a]= malloc(sizeof(OSSL_DISPATCH )*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(OSSL_DISPATCH ))));
    
	memcpy(out[index_a], pos, sizeof(OSSL_DISPATCH )*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(OSSL_DISPATCH ))));
    
	pos += sizeof(OSSL_DISPATCH )*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(OSSL_DISPATCH )));
    
 	}
    //GEN_STRUCT

    
 	void  **provctx;
    
 	provctx = malloc(sizeof(int*)*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))));
    
 	memset(provctx,0, sizeof(int*) * (1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))));
    
 	for ( int index_a= 0; index_a < (1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))) - 1; index_a++ )
 	{

    
	provctx[index_a]= malloc(sizeof(char)*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(char))));
    
	memcpy(provctx[index_a], pos, sizeof(char)*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(char))));
    
	pos += sizeof(char)*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(char)));
    
 	}
    //Call function to be fuzzed, e.g.:

    tls_provider_init(
handle ,in ,out ,provctx 
);

    //FREE

    
	free(handle);
    
	free(in);
    
 	for ( int index_a= 0; index_a < (1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))) - 1; index_a++ )
 	{

    
	free(out[index_a]);
    
 	}
    
 	free(out);
    
 	for ( int index_a= 0; index_a < (1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))) - 1; index_a++ )
 	{

    
	free(provctx[index_a]);
    
 	}
    
 	free(provctx);

  }
  return 0;
}