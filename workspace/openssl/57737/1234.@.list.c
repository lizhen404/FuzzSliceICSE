#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../apps/list.c"

// 1 "../apps/list.c" 2

// 13 "../apps/list.c"


// 14 "../apps/list.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/evp.h"

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/safestack.h"

// 15 "../apps/list.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/err.h"

// 16 "../apps/list.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/provider.h"

// 17 "../apps/list.c" 2



#include "/StaticSlicer/test_lib/openssl/include/openssl/kdf.h"

// 19 "../apps/list.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/encoder.h"

// 20 "../apps/list.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/decoder.h"

// 21 "../apps/list.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/store.h"

// 22 "../apps/list.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/core_names.h"

// 23 "../apps/list.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/rand.h"

// 24 "../apps/list.c" 2

#include "/StaticSlicer/test_lib/openssl/apps/include/apps.h"

#include "/StaticSlicer/test_lib/openssl/apps/include/opt.h"

// 25 "../apps/list.c" 2

#include "/StaticSlicer/test_lib/openssl/apps/include/app_params.h"

// 26 "../apps/list.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/apps/progs.h"

// 27 "../apps/list.c" 2



#include "/StaticSlicer/test_lib/openssl/apps/include/names.h"

// 29 "../apps/list.c" 2



static int verbose = 0;



// 50 "../apps/list.c"

struct stack_st_EVP_CIPHER; typedef int (*sk_EVP_CIPHER_compfunc)(const EVP_CIPHER * const *a, const EVP_CIPHER *const *b); typedef void (*sk_EVP_CIPHER_freefunc)(EVP_CIPHER *a); typedef EVP_CIPHER * (*sk_EVP_CIPHER_copyfunc)(const EVP_CIPHER *a);
struct stack_st_EVP_MD; typedef int (*sk_EVP_MD_compfunc)(const EVP_MD * const *a, const EVP_MD *const *b); typedef void (*sk_EVP_MD_freefunc)(EVP_MD *a); typedef EVP_MD * (*sk_EVP_MD_copyfunc)(const EVP_MD *a);
struct stack_st_EVP_MAC; typedef int (*sk_EVP_MAC_compfunc)(const EVP_MAC * const *a, const EVP_MAC *const *b); typedef void (*sk_EVP_MAC_freefunc)(EVP_MAC *a); typedef EVP_MAC * (*sk_EVP_MAC_copyfunc)(const EVP_MAC *a);
struct stack_st_EVP_KDF; typedef int (*sk_EVP_KDF_compfunc)(const EVP_KDF * const *a, const EVP_KDF *const *b); typedef void (*sk_EVP_KDF_freefunc)(EVP_KDF *a); typedef EVP_KDF * (*sk_EVP_KDF_copyfunc)(const EVP_KDF *a);
struct stack_st_EVP_RAND; typedef int (*sk_EVP_RAND_compfunc)(const EVP_RAND * const *a, const EVP_RAND *const *b); typedef void (*sk_EVP_RAND_freefunc)(EVP_RAND *a); typedef EVP_RAND * (*sk_EVP_RAND_copyfunc)(const EVP_RAND *a);
struct stack_st_OSSL_ENCODER; typedef int (*sk_OSSL_ENCODER_compfunc)(const OSSL_ENCODER * const *a, const OSSL_ENCODER *const *b); typedef void (*sk_OSSL_ENCODER_freefunc)(OSSL_ENCODER *a); typedef OSSL_ENCODER * (*sk_OSSL_ENCODER_copyfunc)(const OSSL_ENCODER *a);
struct stack_st_OSSL_DECODER; typedef int (*sk_OSSL_DECODER_compfunc)(const OSSL_DECODER * const *a, const OSSL_DECODER *const *b); typedef void (*sk_OSSL_DECODER_freefunc)(OSSL_DECODER *a); typedef OSSL_DECODER * (*sk_OSSL_DECODER_copyfunc)(const OSSL_DECODER *a);
struct stack_st_EVP_KEYMGMT; typedef int (*sk_EVP_KEYMGMT_compfunc)(const EVP_KEYMGMT * const *a, const EVP_KEYMGMT *const *b); typedef void (*sk_EVP_KEYMGMT_freefunc)(EVP_KEYMGMT *a); typedef EVP_KEYMGMT * (*sk_EVP_KEYMGMT_copyfunc)(const EVP_KEYMGMT *a);
struct stack_st_EVP_SIGNATURE; typedef int (*sk_EVP_SIGNATURE_compfunc)(const EVP_SIGNATURE * const *a, const EVP_SIGNATURE *const *b); typedef void (*sk_EVP_SIGNATURE_freefunc)(EVP_SIGNATURE *a); typedef EVP_SIGNATURE * (*sk_EVP_SIGNATURE_copyfunc)(const EVP_SIGNATURE *a);
struct stack_st_EVP_KEM; typedef int (*sk_EVP_KEM_compfunc)(const EVP_KEM * const *a, const EVP_KEM *const *b); typedef void (*sk_EVP_KEM_freefunc)(EVP_KEM *a); typedef EVP_KEM * (*sk_EVP_KEM_copyfunc)(const EVP_KEM *a);
struct stack_st_EVP_ASYM_CIPHER; typedef int (*sk_EVP_ASYM_CIPHER_compfunc)(const EVP_ASYM_CIPHER * const *a, const EVP_ASYM_CIPHER *const *b); typedef void (*sk_EVP_ASYM_CIPHER_freefunc)(EVP_ASYM_CIPHER *a); typedef EVP_ASYM_CIPHER * (*sk_EVP_ASYM_CIPHER_copyfunc)(const EVP_ASYM_CIPHER *a);
struct stack_st_EVP_KEYEXCH; typedef int (*sk_EVP_KEYEXCH_compfunc)(const EVP_KEYEXCH * const *a, const EVP_KEYEXCH *const *b); typedef void (*sk_EVP_KEYEXCH_freefunc)(EVP_KEYEXCH *a); typedef EVP_KEYEXCH * (*sk_EVP_KEYEXCH_copyfunc)(const EVP_KEYEXCH *a);
struct stack_st_OSSL_STORE_LOADER; typedef int (*sk_OSSL_STORE_LOADER_compfunc)(const OSSL_STORE_LOADER * const *a, const OSSL_STORE_LOADER *const *b); typedef void (*sk_OSSL_STORE_LOADER_freefunc)(OSSL_STORE_LOADER *a); typedef OSSL_STORE_LOADER * (*sk_OSSL_STORE_LOADER_copyfunc)(const OSSL_STORE_LOADER *a);
struct stack_st_OSSL_PROVIDER; typedef int (*sk_OSSL_PROVIDER_compfunc)(const OSSL_PROVIDER * const *a, const OSSL_PROVIDER *const *b); typedef void (*sk_OSSL_PROVIDER_freefunc)(OSSL_PROVIDER *a); typedef OSSL_PROVIDER * (*sk_OSSL_PROVIDER_copyfunc)(const OSSL_PROVIDER *a); static  inline int sk_OSSL_PROVIDER_num(const struct stack_st_OSSL_PROVIDER *sk) { return OPENSSL_sk_num((const OPENSSL_STACK *)sk); } static  inline OSSL_PROVIDER *sk_OSSL_PROVIDER_value(const struct stack_st_OSSL_PROVIDER *sk, int idx) { return (OSSL_PROVIDER *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); } static  inline struct stack_st_OSSL_PROVIDER *sk_OSSL_PROVIDER_new(sk_OSSL_PROVIDER_compfunc compare) { return (struct stack_st_OSSL_PROVIDER *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); }
static  inline void sk_OSSL_PROVIDER_free(struct stack_st_OSSL_PROVIDER *sk) { OPENSSL_sk_free((OPENSSL_STACK *)sk); }
static  inline int sk_OSSL_PROVIDER_push(struct stack_st_OSSL_PROVIDER *sk, OSSL_PROVIDER *ptr) { return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); }
static  inline void sk_OSSL_PROVIDER_sort(struct stack_st_OSSL_PROVIDER *sk) { OPENSSL_sk_sort((OPENSSL_STACK *)sk); }
static int provider_cmp(const OSSL_PROVIDER * const *a,

const OSSL_PROVIDER * const *b)

{

return strcmp(OSSL_PROVIDER_get0_name(*a), OSSL_PROVIDER_get0_name(*b));

}



static int collect_providers(OSSL_PROVIDER *provider, void *stack)

{

struct stack_st_OSSL_PROVIDER *provider_stack = stack;









return sk_OSSL_PROVIDER_push(provider_stack, provider) > 0 ? 1 : 0;

}



static void list_provider_info(void)

{

struct stack_st_OSSL_PROVIDER *providers = sk_OSSL_PROVIDER_new(provider_cmp);

OSSL_PARAM params[5];

char *name, *version, *buildinfo;

int status;

int i;



if (providers == ((void*)0)) {

BIO_printf(bio_err, "ERROR: Memory allocation\n");

return;

}



if (OSSL_PROVIDER_do_all(((void*)0), &collect_providers, providers) != 1) {

BIO_printf(bio_err, "ERROR: Memory allocation\n");


// clang-format off

/*target_line*/return;

// clang-format on

}



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

    uint8_t * pos = Fuzz_Data;

    //Call function to be fuzzed, e.g.:

    list_provider_info(
 
);

    //FREE


  }
  return 0;
}