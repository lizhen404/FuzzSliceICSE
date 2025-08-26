#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../ssl/statem/statem.c"
// 1 "../ssl/statem/statem.c" 2
// 15 "../ssl/statem/statem.c"
#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"
// 16 "../ssl/statem/statem.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/rand.h"
// 17 "../ssl/statem/statem.c" 2
#include "/StaticSlicer/test_lib/openssl/ssl/ssl_local.h"
#include <assert.h>
// 18 "../ssl/statem/statem.c" 2
#include "/StaticSlicer/test_lib/openssl/ssl/statem/statem_local.h"
// 19 "../ssl/statem/statem.c" 2
// 20 "../ssl/statem/statem.c" 2
// 56 "../ssl/statem/statem.c"
void ossl_statem_send_fatal(SSL_CONNECTION *s, int al)
{

if (s->statem.in_init && s->statem.state == MSG_FLOW_ERROR)
return;
ossl_statem_set_in_init(s, 1);
s->statem.state = MSG_FLOW_ERROR;
if (al != -1)
ssl3_send_alert(s, 2, al);
}







void ossl_statem_fatal(SSL_CONNECTION *s, int al, int reason,
const char *fmt, ...)
{
va_list args;

__builtin_va_start(args, fmt);
ERR_vset_error(20, reason, fmt, args);
__builtin_va_end(args);

ossl_statem_send_fatal(s, al);
}
// 192 "../ssl/statem/statem.c"
void ossl_statem_set_in_init(SSL_CONNECTION *s, int init)
{
s->statem.in_init = init;
if (s->rlayer.rrlmethod != ((void*)0) && s->rlayer.rrlmethod->set_in_init != ((void*)0))
s->rlayer.rrlmethod->set_in_init(s->rlayer.rrl, init);
}

// 242 "../ssl/statem/statem.c"
typedef void (*info_cb) (const SSL *, int, int);

// 352 "../ssl/statem/statem.c"
// 582 "../ssl/statem/statem.c"
// 801 "../ssl/statem/statem.c"
// 979 "../ssl/statem/statem.c"