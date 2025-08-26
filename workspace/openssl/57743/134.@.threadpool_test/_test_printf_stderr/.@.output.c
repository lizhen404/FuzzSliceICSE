#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../test/testutil/output.c"
// 1 "../test/testutil/output.c" 2
// 10 "../test/testutil/output.c"
#include "/StaticSlicer/test_lib/openssl/test/testutil/output.h"
// 11 "../test/testutil/output.c" 2

int test_printf_stderr(const char *fmt, ...)
{
va_list ap;
int ret;

__builtin_va_start(ap, fmt);
ret = test_vprintf_stderr(fmt, ap);
__builtin_va_end(ap);

return ret;
}
