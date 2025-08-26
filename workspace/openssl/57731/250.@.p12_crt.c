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
 + sizeof(int*)+sizeof(char)+sizeof(char)+sizeof(int )+sizeof(int )+sizeof(int )+sizeof(char )+sizeof(char)+sizeof(char )
) continue;

    size_t dyn_size = (int) ((Fuzz_Size - (6
 + sizeof(int*)+sizeof(char)+sizeof(char)+sizeof(int )+sizeof(int )+sizeof(int )+sizeof(char )+sizeof(char)+sizeof(char )
))/6);

    uint8_t * pos = Fuzz_Data;

    //GEN_STRUCT

    
 	struct stack_st_PKCS12_SAFEBAG  **pbags;
    
 	pbags = malloc(sizeof(int*)*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))));
    
 	memset(pbags,0, sizeof(int*) * (1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))));
    
 	for ( int index_a= 0; index_a < (1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))) - 1; index_a++ )
 	{

    
	pbags[index_a]= malloc(sizeof(char)*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(char))));
    
	memcpy(pbags[index_a], pos, sizeof(char)*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(char))));
    
	pos += sizeof(char)*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(char)));
    
 	}
    //GEN_STRUCT

    
 	EVP_PKEY  *key;
    
	key= malloc(sizeof(char)*(1 + (dyn_size/sizeof(char))));
    
 	memset(key,0, sizeof(char) * (1 + (dyn_size/sizeof(char))));
    
	memcpy(key, pos, sizeof(char)* ((1 + (dyn_size/sizeof(char))) - 1));
    
	pos += sizeof(char)* ((1 + (dyn_size/sizeof(char))) - 1);
    //GEN_STRUCT

    
 	int  key_usage;
    
	memcpy(&key_usage, pos, sizeof(int ));
    
	pos += sizeof(int );
    //GEN_STRUCT

    
 	int  iter;
    
	memcpy(&iter, pos, sizeof(int ));
    
	pos += sizeof(int );
    //GEN_STRUCT

    
 	int  nid_key;
    
	memcpy(&nid_key, pos, sizeof(int ));
    
	pos += sizeof(int );
    //GEN_STRUCT

    
 	char  *pass;
    
	pass= malloc(sizeof(char )*(1 + (dyn_size/sizeof(char ))));
    
 	memset(pass,0, sizeof(char ) * (1 + (dyn_size/sizeof(char ))));
    
	memcpy(pass, pos, sizeof(char )* ((1 + (dyn_size/sizeof(char ))) - 1));
    
	pos += sizeof(char )* ((1 + (dyn_size/sizeof(char ))) - 1);
    //GEN_STRUCT

    
 	OSSL_LIB_CTX  *ctx;
    
	ctx= malloc(sizeof(char)*(1 + (dyn_size/sizeof(char))));
    
 	memset(ctx,0, sizeof(char) * (1 + (dyn_size/sizeof(char))));
    
	memcpy(ctx, pos, sizeof(char)* ((1 + (dyn_size/sizeof(char))) - 1));
    
	pos += sizeof(char)* ((1 + (dyn_size/sizeof(char))) - 1);
    //GEN_STRUCT

    
 	char  *propq;
    
	propq= malloc(sizeof(char )*(1 + (dyn_size/sizeof(char ))));
    
 	memset(propq,0, sizeof(char ) * (1 + (dyn_size/sizeof(char ))));
    
	memcpy(propq, pos, sizeof(char )* ((1 + (dyn_size/sizeof(char ))) - 1));
    
	pos += sizeof(char )* ((1 + (dyn_size/sizeof(char ))) - 1);
    //Call function to be fuzzed, e.g.:

    PKCS12_add_key_ex(
pbags ,key ,key_usage ,iter ,nid_key ,pass ,ctx ,propq 
);

    //FREE

    
 	for ( int index_a= 0; index_a < (1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))) - 1; index_a++ )
 	{

    
	free(pbags[index_a]);
    
 	}
    
 	free(pbags);
    
	free(key);
    
	free(pass);
    
	free(ctx);
    
	free(propq);

  }
  return 0;
}