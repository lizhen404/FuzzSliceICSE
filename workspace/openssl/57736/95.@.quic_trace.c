#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../ssl/quic/quic_trace.c"

// 1 "../ssl/quic/quic_trace.c" 2

// 10 "../ssl/quic/quic_trace.c"

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/bio.h"

// 11 "../ssl/quic/quic_trace.c" 2

#include "/StaticSlicer/test_lib/openssl/ssl/ssl_local.h"

#include "/StaticSlicer/test_lib/openssl/include/internal/quic_wire_pkt.h"

// 12 "../ssl/quic/quic_trace.c" 2





static int frame_ack(BIO *bio, PACKET *pkt)

{

OSSL_QUIC_FRAME_ACK ack;

OSSL_QUIC_ACK_RANGE *ack_ranges = ((void*)0);

uint64_t total_ranges = 0;

uint64_t i;



if (!ossl_quic_wire_peek_frame_ack_num_ranges(pkt, &total_ranges)



|| total_ranges > (18446744073709551615UL) / sizeof(ack_ranges[0])

|| (ack_ranges = CRYPTO_zalloc(sizeof(ack_ranges[0]) * (size_t)total_ranges, "../ssl/quic/quic_trace.c", 87)) == ((void*)0))



return 0;



ack.ack_ranges = ack_ranges;

ack.num_ack_ranges = (size_t)total_ranges;





if (!ossl_quic_wire_decode_frame_ack(pkt, 0, &ack, ((void*)0)))


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

    if (Fuzz_Size < 2
 + sizeof(char)+sizeof(PACKET )
) continue;

    size_t dyn_size = (int) ((Fuzz_Size - (2
 + sizeof(char)+sizeof(PACKET )
))/2);

    uint8_t * pos = Fuzz_Data;

    //GEN_STRUCT

    
 	BIO  *bio;
    
	bio= malloc(sizeof(char)*(1 + (dyn_size/sizeof(char))));
    
 	memset(bio,0, sizeof(char) * (1 + (dyn_size/sizeof(char))));
    
	memcpy(bio, pos, sizeof(char)* ((1 + (dyn_size/sizeof(char))) - 1));
    
	pos += sizeof(char)* ((1 + (dyn_size/sizeof(char))) - 1);
    //GEN_STRUCT

    
 	PACKET  *pkt;
    
	pkt= malloc(sizeof(PACKET )*(1 + (dyn_size/sizeof(PACKET ))));
    
 	memset(pkt,0, sizeof(PACKET ) * (1 + (dyn_size/sizeof(PACKET ))));
    
	memcpy(pkt, pos, sizeof(PACKET )* ((1 + (dyn_size/sizeof(PACKET ))) - 1));
    
	pos += sizeof(PACKET )* ((1 + (dyn_size/sizeof(PACKET ))) - 1);
    //Call function to be fuzzed, e.g.:

    frame_ack(
bio ,pkt 
);

    //FREE

    
	free(bio);
    
	free(pkt);

  }
  return 0;
}