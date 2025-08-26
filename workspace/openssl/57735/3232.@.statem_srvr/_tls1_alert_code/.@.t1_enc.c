#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../ssl/t1_enc.c"
// 1 "../ssl/t1_enc.c" 2
// 11 "../ssl/t1_enc.c"
// 12 "../ssl/t1_enc.c" 2
#include "/StaticSlicer/test_lib/openssl/ssl/ssl_local.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/comp.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/evp.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/obj_mac.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/trace.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/ktls.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"
// 13 "../ssl/t1_enc.c" 2
#include "/StaticSlicer/test_lib/openssl/ssl/record/record_local.h"
// 14 "../ssl/t1_enc.c" 2




#include "/StaticSlicer/test_lib/openssl/include/openssl/kdf.h"
// 19 "../ssl/t1_enc.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/rand.h"
// 20 "../ssl/t1_enc.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/core_names.h"
// 22 "../ssl/t1_enc.c" 2



int tls1_alert_code(int code)
{
switch (code) {
case 0:
return 0;
case 10:
return 10;
case 20:
return 20;
case 21:
return 21;
case 22:
return 22;
case 30:
return 30;
case 40:
return 40;
case 41:
return -1;
case 42:
return 42;
case 43:
return 43;
case 44:
return 44;
case 45:
return 45;
case 46:
return 46;
case 47:
return 47;
case 48:
return 48;
case 49:
return 49;
case 50:
return 50;
case 51:
return 51;
case 60:
return 60;
case 70:
return 70;
case 71:
return 71;
case 80:
return 80;
case 90:
return 90;
case 100:
return 100;
case 110:
return 110;
case 111:
return 111;
case 112:
return 112;
case 113:
return 113;
case 114:
return 114;
case 115:
return 115;
case 86:
return 86;
case 120:
return 120;
case 116:
return 40;
case 109:
return 40;
default:
return -1;
}
}