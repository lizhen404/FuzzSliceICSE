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

int main() { 

 	PACKET  *pkt;

 	 sizeof(*pkt);

 	 return 0;
 }