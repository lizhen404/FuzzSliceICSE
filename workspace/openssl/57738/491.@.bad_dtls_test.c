#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../test/bad_dtls_test.c"

// 1 "../test/bad_dtls_test.c" 2

// 30 "../test/bad_dtls_test.c"


// 31 "../test/bad_dtls_test.c" 2



#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/core_names.h"

// 33 "../test/bad_dtls_test.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/params.h"

#include "/StaticSlicer/test_lib/openssl/include/openssl/opensslconf.h"

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/crypto.h"

// 34 "../test/bad_dtls_test.c" 2



#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/bio.h"

// 36 "../test/bad_dtls_test.c" 2



#include "/StaticSlicer/test_lib/openssl/include/openssl/evp.h"

// 38 "../test/bad_dtls_test.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/ssl.h"

// 39 "../test/bad_dtls_test.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/err.h"

// 40 "../test/bad_dtls_test.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/rand.h"

// 41 "../test/bad_dtls_test.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/kdf.h"

// 42 "../test/bad_dtls_test.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/packet.h"

// 43 "../test/bad_dtls_test.c" 2

#include "/StaticSlicer/test_lib/openssl/include/internal/nelem.h"

// 44 "../test/bad_dtls_test.c" 2

#include "/StaticSlicer/test_lib/openssl/test/testutil.h"

// 45 "../test/bad_dtls_test.c" 2









static unsigned char client_random[32];

static unsigned char server_random[32];





static unsigned char session_id[32];

static unsigned char master_secret[48];

static unsigned char cookie[20];





static unsigned char key_block[104];









static EVP_MD_CTX *handshake_md;



static int do_PRF(const void *seed1, int seed1_len,

const void *seed2, int seed2_len,

const void *seed3, int seed3_len,

unsigned char *out, int olen)

{

EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(1021, ((void*)0));

size_t outlen = olen;





EVP_PKEY_derive_init(pctx);

EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_md5_sha1());

EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, master_secret, sizeof(master_secret));

EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, seed1_len);

EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, seed2_len);

EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, seed3_len);

EVP_PKEY_derive(pctx, out, &outlen);

EVP_PKEY_CTX_free(pctx);

return 1;

}



static SSL_SESSION *client_session(void)

{

static unsigned char session_asn1[] = {

0x30, 0x5F,

0x02, 0x01, 0x01,

0x02, 0x02, 0x01, 0x00,

0x04, 0x02, 0x00, 0x2F,

0x04, 0x20,



0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x04, 0x30,



0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

};

const unsigned char *p = session_asn1;





memcpy(session_asn1 + 15, session_id, sizeof(session_id));

memcpy(session_asn1 + 49, master_secret, sizeof(master_secret));



return d2i_SSL_SESSION(((void*)0), &p, sizeof(session_asn1));

}





static int validate_client_hello(BIO *wbio)

{

PACKET pkt, pkt2;

long len;

unsigned char *data;

int cookie_found = 0;

unsigned int u = 0;



if ((len = BIO_ctrl(wbio,3,0,(char *)((char **)&data))) < 0)

return 0;

if (!PACKET_buf_init(&pkt, data, len))

return 0;





if (!PACKET_get_1(&pkt, &u) || u != 22)

return 0;



if (!PACKET_get_net_2(&pkt, &u) || u != 0x0100)

return 0;



if (!PACKET_forward(&pkt, 13 - 3))

return 0;





if (!PACKET_get_1(&pkt, &u) || u != 1)

return 0;



if (!PACKET_forward(&pkt, 12 - 1))

return 0;





if (!PACKET_get_net_2(&pkt, &u) || u != 0x0100)

return 0;





if (!PACKET_copy_bytes(&pkt, client_random, 32))

return 0;





if (!PACKET_get_length_prefixed_1(&pkt, &pkt2) ||

!PACKET_equal(&pkt2, session_id, sizeof(session_id)))

return 0;





if (!PACKET_get_length_prefixed_1(&pkt, &pkt2))

return 0;

if (PACKET_remaining(&pkt2)) {

if (!PACKET_equal(&pkt2, cookie, sizeof(cookie)))

return 0;

cookie_found = 1;

}





if (!PACKET_get_net_2(&pkt, &u) || !PACKET_forward(&pkt, u))

return 0;





if (!PACKET_get_1(&pkt, &u) || !PACKET_forward(&pkt, u))

return 0;





if (!PACKET_get_net_2(&pkt, &u) || !PACKET_forward(&pkt, u))

return 0;





if (PACKET_remaining(&pkt))

return 0;





if (cookie_found && !EVP_DigestUpdate(handshake_md, data + (13 + 12),

len - (13 + 12)))

return 0;



(void)(int)BIO_ctrl(wbio,1,0,((void*)0));



return 1 + cookie_found;

}



static int send_hello_verify(BIO *rbio)

{

static unsigned char hello_verify[] = {

0x16,

0x01, 0x00,

0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x23,

0x03,

0x00, 0x00, 0x17,

0x00, 0x00,

0x00, 0x00, 0x00,

0x00, 0x00, 0x17,

0x01, 0x00,

0x14,



0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00,

};



memcpy(hello_verify + 28, cookie, sizeof(cookie));



BIO_write(rbio, hello_verify, sizeof(hello_verify));



return 1;

}



static int send_server_hello(BIO *rbio)

{

static unsigned char server_hello[] = {

0x16,

0x01, 0x00,

0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

0x00, 0x52,

0x02,

0x00, 0x00, 0x46,

0x00, 0x01,

0x00, 0x00, 0x00,

0x00, 0x00, 0x46,

0x01, 0x00,



0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x20,



0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x00, 0x2f,

0x00,

};

static unsigned char change_cipher_spec[] = {

0x14,

0x01, 0x00,

0x00, 0x00,

0x00, 0x00, 0x00, 0x00, 0x00, 0x02,

0x00, 0x03,

0x01, 0x00, 0x02,

};



memcpy(server_hello + 27, server_random, sizeof(server_random));

memcpy(server_hello + 60, session_id, sizeof(session_id));



if (!EVP_DigestUpdate(handshake_md, server_hello + (13 + 12),

sizeof(server_hello) - (13 + 12)))

return 0;



BIO_write(rbio, server_hello, sizeof(server_hello));

BIO_write(rbio, change_cipher_spec, sizeof(change_cipher_spec));



return 1;

}





static int send_record(BIO *rbio, unsigned char type, uint64_t seqnr,

const void *msg, size_t len)

{







static unsigned char epoch[2] = { 0x00, 0x01 };

static unsigned char seq[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static unsigned char ver[2] = { 0x01, 0x00 };

unsigned char lenbytes[2];

EVP_MAC *hmac = ((void*)0);

EVP_MAC_CTX *ctx = ((void*)0);

EVP_CIPHER_CTX *enc_ctx = ((void*)0);

unsigned char iv[16];

unsigned char pad;

unsigned char *enc;

OSSL_PARAM params[2];

int ret = 0;



seq[0] = (seqnr >> 40) & 0xff;

seq[1] = (seqnr >> 32) & 0xff;

seq[2] = (seqnr >> 24) & 0xff;

seq[3] = (seqnr >> 16) & 0xff;

seq[4] = (seqnr >> 8) & 0xff;

seq[5] = seqnr & 0xff;



pad = 15 - ((len + 20) % 16);

enc = CRYPTO_malloc(len + 20 + 1 + pad, "../test/bad_dtls_test.c", 301);

if (enc == ((void*)0))

return 0;





memcpy(enc, msg, len);





if (!test_ptr("../test/bad_dtls_test.c", 309, "hmac = EVP_MAC_fetch(NULL, \"HMAC\", NULL)", hmac = EVP_MAC_fetch(((void*)0), "HMAC", ((void*)0)))

|| !test_ptr("../test/bad_dtls_test.c", 310, "ctx = EVP_MAC_CTX_new(hmac)", ctx = EVP_MAC_CTX_new(hmac)))

goto end;

params[0] = OSSL_PARAM_construct_utf8_string("digest",

"SHA1", 0);

params[1] = OSSL_PARAM_construct_end();

lenbytes[0] = (unsigned char)(len >> 8);

lenbytes[1] = (unsigned char)(len);

if (!EVP_MAC_init(ctx, (key_block + 20), 20, params)

|| !EVP_MAC_update(ctx, epoch, 2)

|| !EVP_MAC_update(ctx, seq, 6)

|| !EVP_MAC_update(ctx, &type, 1)

|| !EVP_MAC_update(ctx, ver, 2)

|| !EVP_MAC_update(ctx, lenbytes, 2)

|| !EVP_MAC_update(ctx, enc, len)

|| !EVP_MAC_final(ctx, enc + len, ((void*)0), 20))

goto end;





len += 20;

do {

enc[len++] = pad;

} while (len % 16);





if (!test_int_gt("../test/bad_dtls_test.c", 334, "RAND_bytes(iv, sizeof(iv))", "0", RAND_bytes(iv, sizeof(iv)), 0)

|| !test_ptr("../test/bad_dtls_test.c", 335, "enc_ctx = EVP_CIPHER_CTX_new()", enc_ctx = EVP_CIPHER_CTX_new())

|| !test_true("../test/bad_dtls_test.c", 337, "EVP_CipherInit_ex(enc_ctx, EVP_aes_128_cbc(), NULL, enc_key, iv, 1)", (EVP_CipherInit_ex(enc_ctx, EVP_aes_128_cbc(), ((void*)0), (key_block + 56), iv, 1)) != 0)



|| !test_int_ge("../test/bad_dtls_test.c", 338, "EVP_Cipher(enc_ctx, enc, enc, len)", "0", EVP_Cipher(enc_ctx, enc, enc, len), 0))

goto end;





BIO_write(rbio, &type, 1);

BIO_write(rbio, ver, 2);

BIO_write(rbio, epoch, 2);

BIO_write(rbio, seq, 6);

lenbytes[0] = (unsigned char)((len + sizeof(iv)) >> 8);

lenbytes[1] = (unsigned char)(len + sizeof(iv));

BIO_write(rbio, lenbytes, 2);



BIO_write(rbio, iv, sizeof(iv));

BIO_write(rbio, enc, len);

ret = 1;

end:

EVP_MAC_free(hmac);

EVP_MAC_CTX_free(ctx);

EVP_CIPHER_CTX_free(enc_ctx);

CRYPTO_free(enc, "../test/bad_dtls_test.c", 357);

return ret;

}



static int send_finished(SSL *s, BIO *rbio)

{

static unsigned char finished_msg[12 +

12] = {

0x14,

0x00, 0x00, 0x0c,

0x00, 0x03,

0x00, 0x00, 0x00,

0x00, 0x00, 0x0c,



};

unsigned char handshake_hash[64];





do_PRF("\x6b\x65\x79\x20\x65\x78\x70\x61\x6e\x73\x69\x6f\x6e", 13,

server_random, 32,

client_random, 32,

key_block, sizeof(key_block));





if (!EVP_DigestFinal_ex(handshake_md, handshake_hash, ((void*)0)))

return 0;



do_PRF("\x73\x65\x72\x76\x65\x72\x20\x66\x69\x6e\x69\x73\x68\x65\x64", 15,

handshake_hash, EVP_MD_get_size(EVP_MD_CTX_get0_md(handshake_md)),

((void*)0), 0,

finished_msg + 12, 12);



return send_record(rbio, 22, 0,

finished_msg, sizeof(finished_msg));

}



static int validate_ccs(BIO *wbio)

{

PACKET pkt;

long len;

unsigned char *data;

unsigned int u;



len = BIO_ctrl(wbio,3,0,(char *)((char **)&data));

if (len < 0)

return 0;



if (!PACKET_buf_init(&pkt, data, len))

return 0;





if (!PACKET_get_1(&pkt, &u) || u != 20)

return 0;



if (!PACKET_get_net_2(&pkt, &u) || u != 0x0100)

return 0;



if (!PACKET_forward(&pkt, 13 - 3))

return 0;





if (!PACKET_get_1(&pkt, &u) || u != 1)

return 0;





if (!PACKET_get_net_2(&pkt, &u) || u != 0x0002)

return 0;





if (!PACKET_get_1(&pkt, &u) || u != 22)

return 0;

if (!PACKET_get_net_2(&pkt, &u) || u != 0x0100)

return 0;





if (!PACKET_get_net_2(&pkt, &u) || u != 0x0001)

return 0;















return 1;

}









static struct {

uint64_t seq;

int drop;

} tests[] = {

{ 1UL, 0 }, { 3UL, 0 }, { 2UL, 0 },

{ 0x1234UL, 0 }, { 0x1230UL, 0 }, { 0x1235UL, 0 },

{ 0xffffUL, 0 }, { 0x10001UL, 0 }, { 0xfffeUL, 0 }, { 0x10000UL, 0 },

{ 0x10001UL, 1 }, { 0xffUL, 1 }, { 0x100000UL, 0 }, { 0x800000UL, 0 }, { 0x7fffe1UL, 0 },

{ 0xffffffUL, 0 }, { 0x1000000UL, 0 }, { 0xfffffeUL, 0 }, { 0xffffffUL, 1 }, { 0x1000010UL, 0 },

{ 0xfffffdUL, 0 }, { 0x1000011UL, 0 }, { 0x12UL, 1 }, { 0x1000012UL, 0 },

{ 0x1ffffffUL, 0 }, { 0x2000000UL, 0 }, { 0x1ff00feUL, 1 }, { 0x2000001UL, 0 },

{ 0x20fffffUL, 0 }, { 0x2105500UL, 0 }, { 0x20ffffeUL, 1 }, { 0x21054ffUL, 0 },

{ 0x211ffffUL, 0 }, { 0x2110000UL, 1 }, { 0x2120000UL, 0 }



};



static int test_bad_dtls(void)

{

SSL_SESSION *sess = ((void*)0);

SSL_CTX *ctx = ((void*)0);

SSL *con = ((void*)0);

BIO *rbio = ((void*)0);

BIO *wbio = ((void*)0);

time_t now = 0;

int testresult = 0;

int ret;

int i;



RAND_bytes(session_id, sizeof(session_id));

RAND_bytes(master_secret, sizeof(master_secret));

RAND_bytes(cookie, sizeof(cookie));

RAND_bytes(server_random + 4, sizeof(server_random) - 4);



now = time(((void*)0));

memcpy(server_random, &now, sizeof(now));



sess = client_session();

if (!test_ptr("../test/bad_dtls_test.c", 484, "sess", sess))

goto end;



handshake_md = EVP_MD_CTX_new();

if (!test_ptr("../test/bad_dtls_test.c", 488, "handshake_md", handshake_md)

|| !test_true("../test/bad_dtls_test.c", 490, "EVP_DigestInit_ex(handshake_md, EVP_md5_sha1(), NULL)", (EVP_DigestInit_ex(handshake_md, EVP_md5_sha1(), ((void*)0))) != 0))




// clang-format off

/*target_line*/goto end;

// clang-format on



end: ;

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

    uint8_t * pos = Fuzz_Data;

    //Call function to be fuzzed, e.g.:

    test_bad_dtls(
 
);

    //FREE


  }
  return 0;
}