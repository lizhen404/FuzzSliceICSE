#include <stdio.h>

#include <stddef.h>

#include <string.h>

#include <stdint.h>

// 1 "../crypto/sparse_array.c"
// 1 "../crypto/sparse_array.c" 2
// 11 "../crypto/sparse_array.c"
#include "/StaticSlicer/test_lib/openssl/build_ss/include/openssl/crypto.h"
// 12 "../crypto/sparse_array.c" 2
#include "/StaticSlicer/test_lib/openssl/include/openssl/bn.h"
// 13 "../crypto/sparse_array.c" 2
#include "/StaticSlicer/test_lib/openssl/include/crypto/sparse_array.h"
// 14 "../crypto/sparse_array.c" 2
// 51 "../crypto/sparse_array.c"
struct sparse_array_st {
int levels;
ossl_uintmax_t top;
size_t nelem;
void **nodes;
};

OPENSSL_SA *ossl_sa_new(void)
{
OPENSSL_SA *res = CRYPTO_zalloc(sizeof(*res), "../crypto/sparse_array.c", 60);

return res;
}

static void sa_doall(const OPENSSL_SA *sa, void (*node)(void **),
void (*leaf)(ossl_uintmax_t, void *, void *), void *arg)
{
int i[(((int)sizeof(ossl_uintmax_t) * 8 + 4 - 1) / 4)];
void *nodes[(((int)sizeof(ossl_uintmax_t) * 8 + 4 - 1) / 4)];
ossl_uintmax_t idx = 0;
int l = 0;

i[0] = 0;
nodes[0] = sa->nodes;
while (l >= 0) {
const int n = i[l];
void ** const p = nodes[l];

if (n >= (1 << 4)) {
if (p != ((void*)0) && node != ((void*)0))
(*node)(p);
l--;
idx >>= 4;
} else {
i[l] = n + 1;
if (p != ((void*)0) && p[n] != ((void*)0)) {
idx = (idx & ~((1 << 4) - 1)) | n;
if (l < sa->levels - 1) {
i[++l] = 0;
nodes[l] = p[n];
idx <<= 4;
} else if (leaf != ((void*)0)) {
(*leaf)(idx, p[n], arg);
}
}
}
}
}

static void sa_free_node(void **p)
{
CRYPTO_free(p, "../crypto/sparse_array.c", 102);
}

void ossl_sa_free(OPENSSL_SA *sa)
{
if (sa != ((void*)0)) {
sa_doall(sa, &sa_free_node, ((void*)0), ((void*)0));
CRYPTO_free(sa, "../crypto/sparse_array.c", 114);
}
}

struct trampoline_st {
void (*func)(ossl_uintmax_t, void *);
};

void ossl_sa_doall_arg(const OPENSSL_SA *sa,
void (*leaf)(ossl_uintmax_t, void *, void *),
void *arg)
{
if (sa != ((void*)0))
sa_doall(sa, ((void*)0), leaf, arg);
}

static inline void **alloc_node(void)
{
return CRYPTO_zalloc((1 << 4) * sizeof(void *), "../crypto/sparse_array.c", 176);
}

int ossl_sa_set(OPENSSL_SA *sa, ossl_uintmax_t posn, void *val)
{
int i, level = 1;
ossl_uintmax_t n = posn;
void **p;

if (sa == ((void*)0))
return 0;

for (level = 1; level < (((int)sizeof(ossl_uintmax_t) * 8 + 4 - 1) / 4); level++)
if ((n >>= 4) == 0)
break;

for (;sa->levels < level; sa->levels++) {
p = alloc_node();
if (p == ((void*)0))
return 0;
p[0] = sa->nodes;
sa->nodes = p;
}
if (sa->top < posn)
sa->top = posn;

p = sa->nodes;
for (level = sa->levels - 1; level > 0; level--) {
i = (posn >> (4 * level)) & ((1 << 4) - 1);
if (p[i] == ((void*)0) && (p[i] = alloc_node()) == ((void*)0))
return 0;
p = p[i];
}
p += posn & ((1 << 4) - 1);
if (val == ((void*)0) && *p != ((void*)0))
sa->nelem--;
else if (val != ((void*)0) && *p == ((void*)0))
sa->nelem++;
*p = val;
return 1;
}