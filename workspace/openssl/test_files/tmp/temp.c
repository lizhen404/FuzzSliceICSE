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

int main() { 

 	CMP_HDR_TEST_FIXTURE  *fixture;

 	 sizeof(*fixture);

 	 return 0;
 }