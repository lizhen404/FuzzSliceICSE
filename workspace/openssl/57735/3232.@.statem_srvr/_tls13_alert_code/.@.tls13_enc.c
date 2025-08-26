#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../ssl/tls13_enc.c"
// 1 "../ssl/tls13_enc.c" 2
// 10 "../ssl/tls13_enc.c"
#include <stdlib.h>
// 11 "../ssl/tls13_enc.c" 2
#include "/StaticSlicer/test_lib/openssl/ssl/ssl_local.h"
#include "/StaticSlicer/test_lib/openssl/include/openssl/evp.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/ktls.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"
// 12 "../ssl/tls13_enc.c" 2

#include "/StaticSlicer/test_lib/openssl/ssl/record/record_local.h"
// 14 "../ssl/tls13_enc.c" 2


#include "/StaticSlicer/test_lib/openssl/include/openssl/kdf.h"
// 17 "../ssl/tls13_enc.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/core_names.h"
// 18 "../ssl/tls13_enc.c" 2





// 32 "../ssl/tls13_enc.c"
int tls13_alert_code(int code)
{

if (code == 109 || code == 116)
return code;

return tls1_alert_code(code);
}
