#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../test/bioprinttest.c"
// 1 "../test/bioprinttest.c" 2
// 12 "../test/bioprinttest.c"
// 13 "../test/bioprinttest.c" 2
// 14 "../test/bioprinttest.c" 2
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/bio.h"
// 15 "../test/bioprinttest.c" 2
#include "/StaticSlicer/test_lib/openssl/include/internal/numbers.h"
// 16 "../test/bioprinttest.c" 2
#include "/StaticSlicer/test_lib/openssl/test/testutil.h"
// 17 "../test/bioprinttest.c" 2
#include "/StaticSlicer/test_lib/openssl/test/testutil/output.h"
// 18 "../test/bioprinttest.c" 2




















static int tap_level = 0;

int test_vprintf_stderr(const char *fmt, va_list ap)
{
return fprintf(stderr, "%*s# ", tap_level, "") + vfprintf(stderr, fmt, ap);
}

int test_flush_stderr(void)
{
return fflush(stderr);
}
