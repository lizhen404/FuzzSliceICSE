#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../ssl/s3_msg.c"
// 1 "../ssl/s3_msg.c" 2
// 10 "../ssl/s3_msg.c"
#include "/StaticSlicer/test_lib/openssl/ssl/ssl_local.h"
// 11 "../ssl/s3_msg.c" 2

int ssl3_send_alert(SSL_CONNECTION *s, int level, int desc)
{
SSL *ssl = (&(s)->ssl);


if (((!((&(s)->ssl)->method->ssl3_enc->enc_flags & 0x8) && (&(s)->ssl)->method->version >= 0x0304 && (&(s)->ssl)->method->version != 0x10000) || (s)->early_data_state == SSL_EARLY_DATA_CONNECTING || (s)->early_data_state == SSL_EARLY_DATA_CONNECT_RETRY || (s)->early_data_state == SSL_EARLY_DATA_WRITING || (s)->early_data_state == SSL_EARLY_DATA_WRITE_RETRY || (s)->hello_retry_request == SSL_HRR_PENDING))
desc = tls13_alert_code(desc);
else
desc = ssl->method->ssl3_enc->alert_value(desc);
if (s->version == 0x0300 && desc == 70)
desc = 40;

if (desc < 0)
return -1;
if (s->shutdown & 1 && desc != 0)
return -1;

if ((level == 2) && (s->session != ((void*)0)))
SSL_CTX_remove_session(s->session_ctx, s->session);

s->s3.alert_dispatch = 1;
s->s3.send_alert[0] = level;
s->s3.send_alert[1] = desc;
if (!RECORD_LAYER_write_pending(&s->rlayer)) {

return ssl->method->ssl_dispatch_alert(ssl);
}




return -1;
}
