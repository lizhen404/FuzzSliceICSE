# ========================
# Configurable Parameters
# ========================

CC ?= wllvm
BUILD_DIR ?= .
SRC := /StaticSlicer/workspace/openssl/2024-57731/250.@.p12_crt.c
OBJ := /StaticSlicer/workspace/openssl/2024-57731/250.@.p12_crt.o
OUT := /StaticSlicer/workspace/openssl/2024-57731/$(BUILD_DIR)/250.@.p12_crt.out

INCLUDES := \
  -I/StaticSlicer/test_lib/openssl/build_ss \
  -I/StaticSlicer/test_lib/openssl/build_ss/include \
  -I/StaticSlicer/test_lib/openssl/build_ss/providers/common/include \
  -I/StaticSlicer/test_lib/openssl/build_ss/providers/implementations/include \
  -I/StaticSlicer/test_lib/openssl \
  -I/StaticSlicer/test_lib/openssl/include \
  -I/StaticSlicer/test_lib/openssl/providers/common/include \
  -I/StaticSlicer/test_lib/openssl/providers/implementations/include \
  -I/StaticSlicer/test_lib/openssl/build_ss/apps/include \
  -I/StaticSlicer/test_lib/openssl/apps/include

DEFINES := \
  -DAES_ASM -DBSAES_ASM -DCMLL_ASM -DECP_NISTZ256_ASM -DGHASH_ASM -DKECCAK1600_ASM \
  -DMD5_ASM -DOPENSSL_BN_ASM_GF2m -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 \
  -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DPOLY1305_ASM -DRC4_ASM -DSHA1_ASM \
  -DSHA256_ASM -DSHA512_ASM -DVPAES_ASM -DWHIRLPOOL_ASM -DX25519_ASM \
  -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC \
  -DOPENSSLDIR=\"/usr/local/ssl\" \
  -DENGINESDIR=\"/usr/local/lib64/engines-3\" \
  -DMODULESDIR=\"/usr/local/lib64/ossl-modules\" \
  -DOPENSSL_BUILDING_OPENSSL -DNDEBUG

CFLAGS_EXTRA ?=
CFLAGS := -fPIC -pthread -m64 -Wa,--noexecstack -Qunused-arguments -Wall -O0 -w -g $(CFLAGS_EXTRA)
LDFLAGS := -ldl -L/StaticSlicer/test_lib/openssl/build_ss -lcrypto -lssl -lm

# ========================
# Build Rules
# ========================

all: $(OUT)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

$(OUT): $(OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) $(LDFLAGS) $< -o $@

clean:
	rm -f $(OBJ) $(OUT)
