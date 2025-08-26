#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../ssl/record/rec_layer_s3.c"
// 1 "../ssl/record/rec_layer_s3.c" 2
// 10 "../ssl/record/rec_layer_s3.c"
// 11 "../ssl/record/rec_layer_s3.c" 2
#include <limits.h>
// 12 "../ssl/record/rec_layer_s3.c" 2
#include <errno.h>
// 13 "../ssl/record/rec_layer_s3.c" 2
#include <assert.h>
// 14 "../ssl/record/rec_layer_s3.c" 2
#include "/StaticSlicer/test_lib/openssl/ssl/ssl_local.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/buffer.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/evp.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/packet.h"
#include "/StaticSlicer/test_lib/openssl/ssl/quic/quic_local.h"
// 15 "../ssl/record/rec_layer_s3.c" 2



#include "/StaticSlicer/test_lib/openssl/include/openssl/rand.h"
// 19 "../ssl/record/rec_layer_s3.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/core_names.h"
// 20 "../ssl/record/rec_layer_s3.c" 2
#include "/StaticSlicer/test_lib/openssl/ssl/record/record_local.h"
// 21 "../ssl/record/rec_layer_s3.c" 2


int RECORD_LAYER_write_pending(const RECORD_LAYER *rl)
{
return rl->wpend_tot > 0;
}

// 611 "../ssl/record/rec_layer_s3.c"




