#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/property/property_parse.c"
// 1 "../crypto/property/property_parse.c" 2
// 11 "../crypto/property/property_parse.c"
// 12 "../crypto/property/property_parse.c" 2
#include <stdarg.h>
// 13 "../crypto/property/property_parse.c" 2

#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/err.h"
// 15 "../crypto/property/property_parse.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/propertyerr.h"
// 16 "../crypto/property/property_parse.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/property.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/e_os.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/numbers.h"
#include "/StaticSlicer/test_lib/openssl/include/internal/nelem.h"
// 17 "../crypto/property/property_parse.c" 2

#include "/StaticSlicer/test_lib/openssl/include/crypto/ctype.h"
// 19 "../crypto/property/property_parse.c" 2

#include "/StaticSlicer/test_lib/openssl/crypto/property/property_local.h"
// 21 "../crypto/property/property_parse.c" 2


struct stack_st_OSSL_PROPERTY_DEFINITION; typedef int (*sk_OSSL_PROPERTY_DEFINITION_compfunc)(const OSSL_PROPERTY_DEFINITION * const *a, const OSSL_PROPERTY_DEFINITION *const *b); typedef void (*sk_OSSL_PROPERTY_DEFINITION_freefunc)(OSSL_PROPERTY_DEFINITION *a); typedef OSSL_PROPERTY_DEFINITION * (*sk_OSSL_PROPERTY_DEFINITION_copyfunc)(const OSSL_PROPERTY_DEFINITION *a);
void ossl_property_free(OSSL_PROPERTY_LIST *p)
{
CRYPTO_free(p, "../crypto/property/property_parse.c", 531);
}





int ossl_property_parse_init(OSSL_LIB_CTX *ctx)
{
static const char *const predefined_names[] = {
"provider",
"version",
"fips",
"output",
"input",
"structure",
};
size_t i;

for (i = 0; i < (sizeof(predefined_names)/sizeof((predefined_names)[0])); i++)
if (ossl_property_name(ctx, predefined_names[i], 1) == 0)
goto err;






if ((ossl_property_value(ctx, "yes", 1) != 1)
|| (ossl_property_value(ctx, "no", 1) != 2))
goto err;

return 1;
err:
return 0;
}
