#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../ssl/statem/statem_srvr.c"

// 1 "../ssl/statem/statem_srvr.c" 2

// 12 "../ssl/statem/statem_srvr.c"


// 13 "../ssl/statem/statem_srvr.c" 2

#include "/StaticSlicer/test_lib/openssl/ssl/ssl_local.h"

#include "/StaticSlicer/test_lib/openssl/include/openssl/buffer.h"

#include "/StaticSlicer/test_lib/openssl/include/openssl/comp.h"

#include "/StaticSlicer/test_lib/openssl/include/openssl/bn.h"

#include "/StaticSlicer/test_lib/openssl/include/openssl/dh.h"

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/x509.h"

#include "/StaticSlicer/test_lib/openssl/include/openssl/evp.h"

#include "/StaticSlicer/test_lib/openssl/include/openssl/objects.h"

#include "/StaticSlicer/test_lib/openssl/include/openssl/rsa.h"

#include "/StaticSlicer/test_lib/openssl/include/openssl/trace.h"

#include "/StaticSlicer/test_lib/openssl/include/internal/cryptlib.h"

// 14 "../ssl/statem/statem_srvr.c" 2

#include "/StaticSlicer/test_lib/openssl/ssl/statem/statem_local.h"

// 15 "../ssl/statem/statem_srvr.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/constant_time.h"

// 16 "../ssl/statem/statem_srvr.c" 2





#include "/StaticSlicer/test_lib/openssl/include/openssl/rand.h"

// 19 "../ssl/statem/statem_srvr.c" 2













#include "/StaticSlicer/test_lib/openssl/include/openssl/md5.h"

// 26 "../ssl/statem/statem_srvr.c" 2



#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/core_names.h"

// 28 "../ssl/statem/statem_srvr.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/asn1t.h"

// 29 "../ssl/statem/statem_srvr.c" 2









typedef struct {

ASN1_TYPE *kxBlob;

ASN1_TYPE *opaqueBlob;

} GOST_KX_MESSAGE;



extern void GOST_KX_MESSAGE_free(GOST_KX_MESSAGE *a); extern GOST_KX_MESSAGE *d2i_GOST_KX_MESSAGE(GOST_KX_MESSAGE **a, const unsigned char **in, long len);
extern const ASN1_ITEM * GOST_KX_MESSAGE_it(void);



static const ASN1_TEMPLATE GOST_KX_MESSAGE_seq_tt[] = {

{ (0), (0), __builtin_offsetof(GOST_KX_MESSAGE, kxBlob), "kxBlob", (ASN1_ANY_it) },

{ ((0x1)), (0), __builtin_offsetof(GOST_KX_MESSAGE, opaqueBlob), "opaqueBlob", (ASN1_ANY_it) },

} ; const ASN1_ITEM * GOST_KX_MESSAGE_it(void) { static const ASN1_ITEM local_it = { 0x1, 16, GOST_KX_MESSAGE_seq_tt, sizeof(GOST_KX_MESSAGE_seq_tt) / sizeof(ASN1_TEMPLATE), ((void*)0), sizeof(GOST_KX_MESSAGE), "GOST_KX_MESSAGE" }; return &local_it; }



GOST_KX_MESSAGE *d2i_GOST_KX_MESSAGE(GOST_KX_MESSAGE **a, const unsigned char **in, long len) { return (GOST_KX_MESSAGE *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, (GOST_KX_MESSAGE_it())); }
void GOST_KX_MESSAGE_free(GOST_KX_MESSAGE *a) { ASN1_item_free((ASN1_VALUE *)a, (GOST_KX_MESSAGE_it())); }



// 64 "../ssl/statem/statem_srvr.c"

// 179 "../ssl/statem/statem_srvr.c"

// 346 "../ssl/statem/statem_srvr.c"

// 409 "../ssl/statem/statem_srvr.c"

// 1090 "../ssl/statem/statem_srvr.c"

// 1216 "../ssl/statem/statem_srvr.c"

// 1414 "../ssl/statem/statem_srvr.c"

static int tls_process_cke_gost(SSL_CONNECTION *s, PACKET *pkt)

{



EVP_PKEY_CTX *pkey_ctx;

EVP_PKEY *client_pub_pkey = ((void*)0), *pk = ((void*)0);

unsigned char premaster_secret[32];

const unsigned char *start;

size_t outlen = sizeof(premaster_secret), inlen;

unsigned long alg_a;

GOST_KX_MESSAGE *pKX = ((void*)0);

const unsigned char *ptr;

int ret = 0;

SSL_CTX *sctx = ((s)->ssl.ctx);





alg_a = s->s3.tmp.new_cipher->algorithm_auth;

if (alg_a & 0x00000080U) {







pk = s->cert->pkeys[6].privatekey;

if (pk == ((void*)0)) {

pk = s->cert->pkeys[5].privatekey;

}

if (pk == ((void*)0)) {

pk = s->cert->pkeys[4].privatekey;

}

} else if (alg_a & 0x00000020U) {

pk = s->cert->pkeys[4].privatekey;

}



pkey_ctx = EVP_PKEY_CTX_new_from_pkey(sctx->libctx, pk, sctx->propq);

if (pkey_ctx == ((void*)0)) {

(ERR_new(), ERR_set_debug("../ssl/statem/statem_srvr.c", 3227, __func__), ossl_statem_fatal)((s), (80), ((6 | (0x2 << 18L))), ((void*)0));

return 0;

}

if (EVP_PKEY_decrypt_init(pkey_ctx) <= 0) {

(ERR_new(), ERR_set_debug("../ssl/statem/statem_srvr.c", 3231, __func__), ossl_statem_fatal)((s), (80), ((259|((0x1 << 18L)|(0x2 << 18L)))), ((void*)0));


// clang-format off

/*target_line*/return 0;

// clang-format on

}













err: ;

return 0;

}



// 3808 "../ssl/statem/statem_srvr.c"

// 3872 "../ssl/statem/statem_srvr.c"

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
 + sizeof(SSL_CONNECTION )+sizeof(PACKET )
) continue;

    size_t dyn_size = (int) ((Fuzz_Size - (2
 + sizeof(SSL_CONNECTION )+sizeof(PACKET )
))/2);

    uint8_t * pos = Fuzz_Data;

    //GEN_STRUCT

    
 	SSL_CONNECTION  *s;
    
	s= malloc(sizeof(SSL_CONNECTION )*(1 + (dyn_size/sizeof(SSL_CONNECTION ))));
    
 	memset(s,0, sizeof(SSL_CONNECTION ) * (1 + (dyn_size/sizeof(SSL_CONNECTION ))));
    
	memcpy(s, pos, sizeof(SSL_CONNECTION )* ((1 + (dyn_size/sizeof(SSL_CONNECTION ))) - 1));
    
	pos += sizeof(SSL_CONNECTION )* ((1 + (dyn_size/sizeof(SSL_CONNECTION ))) - 1);
    //GEN_STRUCT

    
 	PACKET  *pkt;
    
	pkt= malloc(sizeof(PACKET )*(1 + (dyn_size/sizeof(PACKET ))));
    
 	memset(pkt,0, sizeof(PACKET ) * (1 + (dyn_size/sizeof(PACKET ))));
    
	memcpy(pkt, pos, sizeof(PACKET )* ((1 + (dyn_size/sizeof(PACKET ))) - 1));
    
	pos += sizeof(PACKET )* ((1 + (dyn_size/sizeof(PACKET ))) - 1);
    //Call function to be fuzzed, e.g.:

    tls_process_cke_gost(
s ,pkt 
);

    //FREE

    
	free(s);
    
	free(pkt);

  }
  return 0;
}