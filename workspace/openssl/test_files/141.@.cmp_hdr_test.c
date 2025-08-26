#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../test/cmp_hdr_test.c"

// 1 "../test/cmp_hdr_test.c" 2

// 12 "../test/cmp_hdr_test.c"

#include "/StaticSlicer/test_lib/openssl/test/helpers/cmp_testlib.h"

// 13 "../test/cmp_hdr_test.c" 2







typedef struct test_fixture {

const char *test_case_name;

int expected;

OSSL_CMP_CTX *cmp_ctx;

OSSL_CMP_PKIHEADER *hdr;



} CMP_HDR_TEST_FIXTURE;



static int execute_HDR_set1_recipient_test(CMP_HDR_TEST_FIXTURE *fixture)

{

X509_NAME *x509name = X509_NAME_new();



if (!test_ptr("../test/cmp_hdr_test.c", 136, "x509name", x509name))

return 0;



X509_NAME_add_entry_by_txt((x509name), ("CN"), (0x1000|1), (unsigned char *)("A common recipient name"), -1, -1, 0);

if (!test_int_eq("../test/cmp_hdr_test.c", 140, "ossl_cmp_hdr_set1_recipient(fixture->hdr, x509name)", "1", ossl_cmp_hdr_set1_recipient(fixture->hdr, x509name), 1))


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

    if (Fuzz_Size < 1
 + sizeof(CMP_HDR_TEST_FIXTURE )
) continue;

    size_t dyn_size = (int) ((Fuzz_Size - (1
 + sizeof(CMP_HDR_TEST_FIXTURE )
))/1);

    uint8_t * pos = Fuzz_Data;

    //GEN_STRUCT

    
 	CMP_HDR_TEST_FIXTURE  *fixture;
    
	fixture= malloc(sizeof(CMP_HDR_TEST_FIXTURE )*(1 + (dyn_size/sizeof(CMP_HDR_TEST_FIXTURE ))));
    
 	memset(fixture,0, sizeof(CMP_HDR_TEST_FIXTURE ) * (1 + (dyn_size/sizeof(CMP_HDR_TEST_FIXTURE ))));
    
	memcpy(fixture, pos, sizeof(CMP_HDR_TEST_FIXTURE )* ((1 + (dyn_size/sizeof(CMP_HDR_TEST_FIXTURE ))) - 1));
    
	pos += sizeof(CMP_HDR_TEST_FIXTURE )* ((1 + (dyn_size/sizeof(CMP_HDR_TEST_FIXTURE ))) - 1);
    //Call function to be fuzzed, e.g.:

    execute_HDR_set1_recipient_test(
fixture 
);

    //FREE

    
	free(fixture);

  }
  return 0;
}