#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../test/testutil/tests.c"
// 1 "../test/testutil/tests.c" 2
// 10 "../test/testutil/tests.c"
#include "/StaticSlicer/test_lib/openssl/test/testutil.h"
#include <errno.h>
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/asn1.h"
// 11 "../test/testutil/tests.c" 2
#include "/StaticSlicer/test_lib/openssl/test/testutil/output.h"
// 12 "../test/testutil/tests.c" 2
#include "/StaticSlicer/test_lib/openssl/test/testutil/tu_local.h"
// 13 "../test/testutil/tests.c" 2



#include <ctype.h>
// 17 "../test/testutil/tests.c" 2








void test_fail_message_prefix(const char *prefix, const char *file,
int line, const char *type,
const char *left, const char *right,
const char *op)
{
test_printf_stderr("%s: ", prefix != ((void*)0) ? prefix : "ERROR");
if (type)
test_printf_stderr("(%s) ", type);
if (op != ((void*)0)) {
if (left != ((void*)0) && right != ((void*)0))
test_printf_stderr("'%s %s %s' failed", left, op, right);
else
test_printf_stderr("'%s'", op);
}
if (file != ((void*)0)) {
test_printf_stderr(" @ %s:%d", file, line);
}
test_printf_stderr("\n");
}
// 68 "../test/testutil/tests.c"
static void test_fail_message(const char *prefix, const char *file, int line,
const char *type, const char *left,
const char *right, const char *op,
const char *fmt, ...)
;

static void test_fail_message_va(const char *prefix, const char *file,
int line, const char *type,
const char *left, const char *right,
const char *op, const char *fmt, va_list ap)
{
test_fail_message_prefix(prefix, file, line, type, left, right, op);
if (fmt != ((void*)0)) {
test_vprintf_stderr(fmt, ap);
test_printf_stderr("\n");
}
test_flush_stderr();
}

static void test_fail_message(const char *prefix, const char *file,
int line, const char *type,
const char *left, const char *right,
const char *op, const char *fmt, ...)
{
va_list ap;

__builtin_va_start(ap, fmt);
test_fail_message_va(prefix, file, line, type, left, right, op, fmt, ap);
__builtin_va_end(ap);
}

// 231 "../test/testutil/tests.c"
int test_int_eq(const char *file, int line, const char *s1, const char *s2, const int t1, const int t2) { if (t1 == t2) return 1; test_fail_message(((void*)0), file, line, "int", s1, s2, "==", "[%d] compared to [%d]", (int)t1, (int)t2); return 0; }
int test_ptr(const char *file, int line, const char *s, const void *p)
{
if (p != ((void*)0))
return 1;
test_fail_message(((void*)0), file, line, "ptr", s, "NULL", "!=", "%p", p);
return 0;
}

// 382 "../test/testutil/tests.c"
// 468 "../test/testutil/tests.c"