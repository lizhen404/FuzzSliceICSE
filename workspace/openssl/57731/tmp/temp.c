#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/pkcs12/p12_crt.c"

// 1 "../crypto/pkcs12/p12_crt.c" 2

// 10 "../crypto/pkcs12/p12_crt.c"


// 11 "../crypto/pkcs12/p12_crt.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"

// 12 "../crypto/pkcs12/p12_crt.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/pkcs12.h"

// 13 "../crypto/pkcs12/p12_crt.c" 2

#include "/StaticSlicer/test_lib/openssl/crypto/pkcs12/p12_local.h"

// 14 "../crypto/pkcs12/p12_crt.c" 2



static int pkcs12_add_bag(struct stack_st_PKCS12_SAFEBAG **pbags,

PKCS12_SAFEBAG *bag);

PKCS12_SAFEBAG *PKCS12_add_key_ex(struct stack_st_PKCS12_SAFEBAG **pbags,

EVP_PKEY *key, int key_usage, int iter,

int nid_key, const char *pass,

OSSL_LIB_CTX *ctx, const char *propq)

{



PKCS12_SAFEBAG *bag = ((void*)0);

PKCS8_PRIV_KEY_INFO *p8 = ((void*)0);





if ((p8 = EVP_PKEY2PKCS8(key)) == ((void*)0))

goto err;

if (key_usage && !PKCS8_add_keyusage(p8, key_usage))


// clang-format off

/*target_line*/goto err;

// clang-format on

return 0;

err: ;

return 0;

}



static int pkcs12_add_bag(struct stack_st_PKCS12_SAFEBAG **pbags,

PKCS12_SAFEBAG *bag)

{

int free_bags = 0;



if (pbags == ((void*)0))

return 1;

if (*pbags == ((void*)0)) {

*pbags = ((struct stack_st_PKCS12_SAFEBAG *)OPENSSL_sk_new_null());

if (*pbags == ((void*)0))

return 0;

free_bags = 1;

}



if (!OPENSSL_sk_push(ossl_check_PKCS12_SAFEBAG_sk_type(*pbags), ossl_check_PKCS12_SAFEBAG_type(bag))) {

if (free_bags) {

OPENSSL_sk_free(ossl_check_PKCS12_SAFEBAG_sk_type(*pbags));

*pbags = ((void*)0);

}

return 0;

}



return 1;



}



// Fuzzing wrapper body

int main() { 

 	char  *propq;

 	 sizeof(*propq);

 	 return 0;
 }