#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../ssl/quic/quic_wire.c"
// 1 "../ssl/quic/quic_wire.c" 2
// 10 "../ssl/quic/quic_wire.c"
#include "/StaticSlicer/test_lib/openssl/include/openssl/macros.h"
// 11 "../ssl/quic/quic_wire.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/objects.h"
// 12 "../ssl/quic/quic_wire.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/quic_ssl.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/quic_vlint.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/quic_wire.h"
// 13 "../ssl/quic/quic_wire.c" 2


#include "/StaticSlicer/test_lib/openssl/include/internal/quic_error.h"
// 16 "../ssl/quic/quic_wire.c" 2

static inline  uint64_t safe_mul_uint64_t(uint64_t a, uint64_t b, int *err) { uint64_t r; if (!__builtin_mul_overflow(a, b, &r)) return r; *err |= 1; return a * b; }
int ossl_quic_wire_skip_frame_header(PACKET *pkt, uint64_t *type)
{
return PACKET_get_quic_vlint(pkt, type);
}

static int expect_frame_header_mask(PACKET *pkt,
uint64_t expected_frame_type,
uint64_t mask_bits,
uint64_t *actual_frame_type)
{
uint64_t actual_frame_type_;

if (!ossl_quic_wire_skip_frame_header(pkt, &actual_frame_type_)
|| (actual_frame_type_ & ~mask_bits) != expected_frame_type)
return 0;

if (actual_frame_type != ((void*)0))
*actual_frame_type = actual_frame_type_;

return 1;
}

int ossl_quic_wire_peek_frame_ack_num_ranges(const PACKET *orig_pkt,
uint64_t *total_ranges)
{
PACKET pkt = *orig_pkt;
uint64_t ack_range_count, i;

if (!expect_frame_header_mask(&pkt, 0x02,
1, ((void*)0))
|| !PACKET_skip_quic_vlint(&pkt)
|| !PACKET_skip_quic_vlint(&pkt)
|| !PACKET_get_quic_vlint(&pkt, &ack_range_count))
return 0;
// 507 "../ssl/quic/quic_wire.c"
for (i = 0; i < ack_range_count; ++i)
if (!PACKET_skip_quic_vlint(&pkt)
|| !PACKET_skip_quic_vlint(&pkt))
return 0;


*total_ranges = ack_range_count + 1;
return 1;
}

int ossl_quic_wire_decode_frame_ack(PACKET *pkt,
uint32_t ack_delay_exponent,
OSSL_QUIC_FRAME_ACK *ack,
uint64_t *total_ranges) {
uint64_t frame_type, largest_ackd, ack_delay_raw;
uint64_t ack_range_count, first_ack_range, start, end, i;


if (!expect_frame_header_mask(pkt, 0x02,
1, &frame_type)
|| !PACKET_get_quic_vlint(pkt, &largest_ackd)
|| !PACKET_get_quic_vlint(pkt, &ack_delay_raw)
|| !PACKET_get_quic_vlint(pkt, &ack_range_count)
|| !PACKET_get_quic_vlint(pkt, &first_ack_range))
return 0;

if (first_ack_range > largest_ackd)
return 0;

if (ack_range_count > (18446744073709551615UL) )
return 0;

start = largest_ackd - first_ack_range;

if (ack != ((void*)0)) {
int err = 0;
ack->delay_time
= ossl_time_multiply(ossl_ticks2time(((((uint64_t)1000000000) / 1000) / 1000)),
safe_mul_uint64_t(ack_delay_raw,
(uint64_t)1 << ack_delay_exponent,
&err));
if (err)
ack->delay_time = ossl_time_infinite();

if (ack->num_ack_ranges > 0) {
ack->ack_ranges[0].end = largest_ackd;
ack->ack_ranges[0].start = start;
}
}

for (i = 0; i < ack_range_count; ++i) {
uint64_t gap, len;

if (!PACKET_get_quic_vlint(pkt, &gap)
|| !PACKET_get_quic_vlint(pkt, &len))
return 0;

end = start - gap - 2;
if (start < gap + 2 || len > end)
return 0;

if (ack != ((void*)0) && i + 1 < ack->num_ack_ranges) {
ack->ack_ranges[i + 1].start = start = end - len;
ack->ack_ranges[i + 1].end = end;
}
}

if (ack != ((void*)0) && ack_range_count + 1 < ack->num_ack_ranges)
ack->num_ack_ranges = (size_t)ack_range_count + 1;

if (total_ranges != ((void*)0))
*total_ranges = ack_range_count + 1;

if (frame_type == 0x03) {
uint64_t ect0, ect1, ecnce;

if (!PACKET_get_quic_vlint(pkt, &ect0)
|| !PACKET_get_quic_vlint(pkt, &ect1)
|| !PACKET_get_quic_vlint(pkt, &ecnce))
return 0;

if (ack != ((void*)0)) {
ack->ect0 = ect0;
ack->ect1 = ect1;
ack->ecnce = ecnce;
ack->ecn_present = 1;
}
} else if (ack != ((void*)0)) {
ack->ecn_present = 0;
}

return 1;
}
