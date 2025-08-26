#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../test/threadpool_test.c"

// 1 "../test/threadpool_test.c" 2

// 10 "../test/threadpool_test.c"


// 11 "../test/threadpool_test.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"

// 12 "../test/threadpool_test.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/thread_arch.h"

// 13 "../test/threadpool_test.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/thread.h"

// 14 "../test/threadpool_test.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/thread.h"

// 15 "../test/threadpool_test.c" 2

#include "/StaticSlicer/test_lib/openssl/test/testutil.h"

// 16 "../test/threadpool_test.c" 2



static uint32_t test_thread_native_fn(void *data)

{

uint32_t *ldata = (uint32_t*) data;

*ldata = *ldata + 1;

return *ldata - 1;

}





static int test_thread_internal(void)

{

uint32_t retval[3];

uint32_t local[3] = { 0 };

uint32_t threads_supported;

size_t i;

void *t[3];

OSSL_LIB_CTX *cust_ctx = OSSL_LIB_CTX_new();



threads_supported = OSSL_get_thread_support_flags();

threads_supported &= (1U<<1);



if (threads_supported == 0) {

if (!test_uint64_t_eq("../test/threadpool_test.c", 109, "OSSL_get_max_threads(NULL)", "0", OSSL_get_max_threads(((void*)0)), 0))

return 0;

if (!test_uint64_t_eq("../test/threadpool_test.c", 111, "OSSL_get_max_threads(cust_ctx)", "0", OSSL_get_max_threads(cust_ctx), 0))

return 0;



if (!test_int_eq("../test/threadpool_test.c", 114, "OSSL_set_max_threads(NULL, 1)", "0", OSSL_set_max_threads(((void*)0), 1), 0))

return 0;

if (!test_int_eq("../test/threadpool_test.c", 116, "OSSL_set_max_threads(cust_ctx, 1)", "0", OSSL_set_max_threads(cust_ctx, 1), 0))

return 0;



if (!test_uint64_t_eq("../test/threadpool_test.c", 119, "OSSL_get_max_threads(NULL)", "0", OSSL_get_max_threads(((void*)0)), 0))

return 0;

if (!test_uint64_t_eq("../test/threadpool_test.c", 121, "OSSL_get_max_threads(cust_ctx)", "0", OSSL_get_max_threads(cust_ctx), 0))

return 0;



t[0] = ossl_crypto_thread_start(((void*)0), test_thread_native_fn, &local[0]);

if (!test_ptr_null("../test/threadpool_test.c", 125, "t[0]", t[0]))

return 0;



return 1;

}







if (!test_uint64_t_eq("../test/threadpool_test.c", 133, "OSSL_get_max_threads(NULL)", "0", OSSL_get_max_threads(((void*)0)), 0))


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

    uint8_t * pos = Fuzz_Data;

    //Call function to be fuzzed, e.g.:

    test_thread_internal(
 
);

    //FREE


  }
  return 0;
}