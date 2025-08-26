#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/x509/v3_addr.c"

// 1 "../crypto/x509/v3_addr.c" 2

// 14 "../crypto/x509/v3_addr.c"


// 15 "../crypto/x509/v3_addr.c" 2

#include <stdlib.h>

// 16 "../crypto/x509/v3_addr.c" 2

#include <assert.h>

// 17 "../crypto/x509/v3_addr.c" 2


// 18 "../crypto/x509/v3_addr.c" 2



#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/conf.h"

// 20 "../crypto/x509/v3_addr.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/asn1.h"

// 21 "../crypto/x509/v3_addr.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/asn1t.h"

// 22 "../crypto/x509/v3_addr.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/buffer.h"

// 23 "../crypto/x509/v3_addr.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/x509v3.h"

// 24 "../crypto/x509/v3_addr.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"

// 25 "../crypto/x509/v3_addr.c" 2

#include "/StaticSlicer/test_lib/openssl/include/crypto/asn1.h"

// 26 "../crypto/x509/v3_addr.c" 2

#include "/StaticSlicer/test_lib/openssl/include/crypto/x509.h"

// 27 "../crypto/x509/v3_addr.c" 2

#include "/StaticSlicer/test_lib/openssl/crypto/x509/ext_dat.h"

// 28 "../crypto/x509/v3_addr.c" 2

#include "/StaticSlicer/test_lib/openssl/crypto/x509/x509_local.h"

// 29 "../crypto/x509/v3_addr.c" 2















static const ASN1_TEMPLATE IPAddressRange_seq_tt[] = {

{ (0), (0), __builtin_offsetof(IPAddressRange, min), "min", (ASN1_BIT_STRING_it) },

{ (0), (0), __builtin_offsetof(IPAddressRange, max), "max", (ASN1_BIT_STRING_it) }

} ; const ASN1_ITEM * IPAddressRange_it(void) { static const ASN1_ITEM local_it = { 0x1, 16, IPAddressRange_seq_tt, sizeof(IPAddressRange_seq_tt) / sizeof(ASN1_TEMPLATE), ((void*)0), sizeof(IPAddressRange), "IPAddressRange" }; return &local_it; }



static const ASN1_TEMPLATE IPAddressOrRange_ch_tt[] = {

{ (0), (0), __builtin_offsetof(IPAddressOrRange, u.addressPrefix), "u.addressPrefix", (ASN1_BIT_STRING_it) },

{ (0), (0), __builtin_offsetof(IPAddressOrRange, u.addressRange), "u.addressRange", (IPAddressRange_it) }

} ; const ASN1_ITEM * IPAddressOrRange_it(void) { static const ASN1_ITEM local_it = { 0x2, __builtin_offsetof(IPAddressOrRange, type) , IPAddressOrRange_ch_tt, sizeof(IPAddressOrRange_ch_tt) / sizeof(ASN1_TEMPLATE), ((void*)0), sizeof(IPAddressOrRange), "IPAddressOrRange" }; return &local_it; }






IPAddressOrRange *IPAddressOrRange_new(void) { return (IPAddressOrRange *)ASN1_item_new((IPAddressOrRange_it())); } void IPAddressOrRange_free(IPAddressOrRange *a) { ASN1_item_free((ASN1_VALUE *)a, (IPAddressOrRange_it())); }

// 74 "../crypto/x509/v3_addr.c"

// 132 "../crypto/x509/v3_addr.c"

// 285 "../crypto/x509/v3_addr.c"

static int make_addressPrefix(IPAddressOrRange **result, unsigned char *addr,

const int prefixlen, const int afilen)

{

int bytelen = (prefixlen + 7) / 8, bitlen = prefixlen % 8;

IPAddressOrRange *aor = IPAddressOrRange_new();



if (prefixlen < 0 || prefixlen > (afilen * 8))


// clang-format off

/*target_line*/return 0;

// clang-format on

return 0;

err: ;

return 0;

}













// 694 "../crypto/x509/v3_addr.c"











// 1232 "../crypto/x509/v3_addr.c"

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

    if (Fuzz_Size < 3
 + sizeof(int*)+sizeof(IPAddressOrRange )+sizeof(unsigned )+sizeof(int )+sizeof(int )
) continue;

    size_t dyn_size = (int) ((Fuzz_Size - (3
 + sizeof(int*)+sizeof(IPAddressOrRange )+sizeof(unsigned )+sizeof(int )+sizeof(int )
))/3);

    uint8_t * pos = Fuzz_Data;

    //GEN_STRUCT

    
 	IPAddressOrRange  **result;
    
 	result = malloc(sizeof(int*)*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))));
    
 	memset(result,0, sizeof(int*) * (1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))));
    
 	for ( int index_a= 0; index_a < (1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))) - 1; index_a++ )
 	{

    
	result[index_a]= malloc(sizeof(IPAddressOrRange )*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(IPAddressOrRange ))));
    
	memcpy(result[index_a], pos, sizeof(IPAddressOrRange )*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(IPAddressOrRange ))));
    
	pos += sizeof(IPAddressOrRange )*(1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(IPAddressOrRange )));
    
 	}
    //GEN_STRUCT

    
 	unsigned  *addr;
    
	addr= malloc(sizeof(unsigned )*(1 + (dyn_size/sizeof(unsigned ))));
    
 	memset(addr,0, sizeof(unsigned ) * (1 + (dyn_size/sizeof(unsigned ))));
    
	memcpy(addr, pos, sizeof(unsigned )* ((1 + (dyn_size/sizeof(unsigned ))) - 1));
    
	pos += sizeof(unsigned )* ((1 + (dyn_size/sizeof(unsigned ))) - 1);
    //GEN_STRUCT

    
 	int  prefixlen;
    
	memcpy(&prefixlen, pos, sizeof(int ));
    
	pos += sizeof(int );
    //GEN_STRUCT

    
 	int  afilen;
    
	memcpy(&afilen, pos, sizeof(int ));
    
	pos += sizeof(int );
    //Call function to be fuzzed, e.g.:

    make_addressPrefix(
result ,addr ,prefixlen ,afilen 
);

    //FREE

    
 	for ( int index_a= 0; index_a < (1 + (int)(floor(pow(dyn_size, 1./2))/sizeof(int*))) - 1; index_a++ )
 	{

    
	free(result[index_a]);
    
 	}
    
 	free(result);
    
	free(addr);

  }
  return 0;
}