#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../test/v3ext.c"

// 1 "../test/v3ext.c" 2

// 10 "../test/v3ext.c"


// 11 "../test/v3ext.c" 2


// 12 "../test/v3ext.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/x509.h"

// 13 "../test/v3ext.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/x509v3.h"

// 14 "../test/v3ext.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/pem.h"

// 15 "../test/v3ext.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/err.h"

// 16 "../test/v3ext.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/nelem.h"

// 17 "../test/v3ext.c" 2



#include "/StaticSlicer/test_lib/openssl/test/testutil.h"

// 19 "../test/v3ext.c" 2







static struct ip_ranges_st {

const unsigned int afi;

const char *ip1;

const char *ip2;

int rorp;

} ranges[] = {

{ 1, "192.168.0.0", "192.168.0.1", 0},

{ 1, "192.168.0.0", "192.168.0.2", 1},

{ 1, "192.168.0.0", "192.168.0.3", 0},

{ 1, "192.168.0.0", "192.168.0.254", 1},

{ 1, "192.168.0.0", "192.168.0.255", 0},

{ 1, "192.168.0.1", "192.168.0.255", 1},

{ 1, "192.168.0.1", "192.168.0.1", 0},

{ 1, "192.168.0.0", "192.168.255.255", 0},

{ 1, "192.168.1.0", "192.168.255.255", 1},

{ 2, "2001:0db8::0", "2001:0db8::1", 0},

{ 2, "2001:0db8::0", "2001:0db8::2", 1},

{ 2, "2001:0db8::0", "2001:0db8::3", 0},

{ 2, "2001:0db8::0", "2001:0db8::fffe", 1},

{ 2, "2001:0db8::0", "2001:0db8::ffff", 0},

{ 2, "2001:0db8::1", "2001:0db8::ffff", 1},

{ 2, "2001:0db8::1", "2001:0db8::1", 0},

{ 2, "2001:0db8::0:0", "2001:0db8::ffff:ffff", 0},

{ 2, "2001:0db8::1:0", "2001:0db8::ffff:ffff", 1}

};



static int test_addr_fam_len(void)

{

int testresult = 0;

IPAddrBlocks *addr = ((void*)0);

IPAddressFamily *f1 = ((void*)0);

ASN1_OCTET_STRING *ip1 = ((void*)0), *ip2 = ((void*)0);

unsigned char key[6];

unsigned int keylen;

unsigned afi = 1;





addr = ((struct stack_st_IPAddressFamily *)OPENSSL_sk_new_null());

if (!test_ptr("../test/v3ext.c", 241, "addr", addr))

goto end;

ip1 = a2i_IPADDRESS(ranges[0].ip1);

if (!test_ptr("../test/v3ext.c", 244, "ip1", ip1))

goto end;

ip2 = a2i_IPADDRESS(ranges[0].ip2);

if (!test_ptr("../test/v3ext.c", 247, "ip2", ip2))

goto end;

if (!test_true("../test/v3ext.c", 249, "X509v3_addr_add_range(addr, ranges[0].afi, NULL, ip1->data, ip2->data)", (X509v3_addr_add_range(addr, ranges[0].afi, ((void*)0), ip1->data, ip2->data)) != 0))

goto end;

if (!test_true("../test/v3ext.c", 251, "X509v3_addr_is_canonical(addr)", (X509v3_addr_is_canonical(addr)) != 0))

goto end;





key[0] = (afi >> 8) & 0xFF;

key[1] = afi & 0xFF;

key[2] = 0xD;

key[3] = 0xE;

key[4] = 0xA;

key[5] = 0xD;

keylen = 6;

if ((f1 = IPAddressFamily_new()) == ((void*)0))

goto end;

if (f1->ipAddressChoice == ((void*)0) &&

(f1->ipAddressChoice = IPAddressChoice_new()) == ((void*)0))


// clang-format off

/*target_line*/goto end;

// clang-format on

end: ;

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

    test_addr_fam_len(
 
);

    //FREE


  }
  return 0;
}