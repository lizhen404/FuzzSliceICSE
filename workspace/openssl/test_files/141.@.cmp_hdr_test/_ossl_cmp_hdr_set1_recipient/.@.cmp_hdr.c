#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/cmp/cmp_hdr.c"
// 1 "../crypto/cmp/cmp_hdr.c" 2
// 14 "../crypto/cmp/cmp_hdr.c"
#include "/StaticSlicer/test_lib/openssl/crypto/cmp/cmp_local.h"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/err.h"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/cmp.h"
// 15 "../crypto/cmp/cmp_hdr.c" 2

#include "/StaticSlicer/test_lib/openssl/include/openssl/rand.h"
// 17 "../crypto/cmp/cmp_hdr.c" 2


#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/asn1t.h"
// 20 "../crypto/cmp/cmp_hdr.c" 2



static int set1_general_name(GENERAL_NAME **tgt, const X509_NAME *src)
{
GENERAL_NAME *name;

if (!__builtin_expect(!!((tgt != ((void*)0)) != 0), 1))
return 0;
if ((name = GENERAL_NAME_new()) == ((void*)0))
goto err;
name->type = 4;

if (src == ((void*)0)) {
if ((name->d.directoryName = X509_NAME_new()) == ((void*)0))
goto err;
} else if (!X509_NAME_set(&name->d.directoryName, src)) {
goto err;
}

GENERAL_NAME_free(*tgt);
*tgt = name;

return 1;

err:
GENERAL_NAME_free(name);
return 0;
}






int ossl_cmp_hdr_set1_recipient(OSSL_CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
if (!__builtin_expect(!!((hdr != ((void*)0)) != 0), 1))
return 0;
return set1_general_name(&hdr->recipient, nm);
}

// 281 "../crypto/cmp/cmp_hdr.c"