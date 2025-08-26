# ========================
# Configurable Parameters
# ========================

CC ?= wllvm
CFLAGS_EXTRA ?=
CFLAGS = -pthread -m64 -Wa,--noexecstack -Qunused-arguments -Wall -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -O0 -w -g $(CFLAGS_EXTRA)
INCLUDES := \
  -I/StaticSlicer/test_lib/openssl/build_ss \
  -I/StaticSlicer/test_lib/openssl/build_ss/include \
  -I/StaticSlicer/test_lib/openssl/build_ss/apps/include \
  -I/StaticSlicer/test_lib/openssl/include \
  -I/StaticSlicer/test_lib/openssl/apps/include \
  -I/StaticSlicer/test_lib/openssl

OPENSSL_DEFS := \
  -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC \
  -DOPENSSLDIR=\"/usr/local/ssl\" \
  -DENGINESDIR=\"/usr/local/lib64/engines-3\" \
  -DMODULESDIR=\"/usr/local/lib64/ossl-modules\"

SRC_DIR := /StaticSlicer/workspace/openssl/2024-57729/141.@.cmp_hdr_test
BUILD_OBJS := \
  $(SRC_DIR).o \
  $(SRC_DIR)/_ossl_cmp_hdr_set1_recipient/.@.cmp_hdr.o \
  $(SRC_DIR)/_test_ptr/.@.tests.o \
  $(SRC_DIR)/_test_vprintf_stderr/.@.bioprinttest.o \
  $(SRC_DIR)/_test_printf_stderr/.@.output.o

# OUTPUT := $(SRC_DIR).out
BUILD_DIR ?= .
OUTPUT := $(BUILD_DIR)/$(notdir $(SRC_DIR)).out

# ========================
# Build Rules
# ========================

all: $(OUTPUT)

$(SRC_DIR).o: $(SRC_DIR).c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(SRC_DIR)/_ossl_cmp_hdr_set1_recipient/.@.cmp_hdr.o: $(SRC_DIR)/_ossl_cmp_hdr_set1_recipient/.@.cmp_hdr.c
	$(CC) $(CFLAGS) $(INCLUDES) -DAES_ASM -DBSAES_ASM -DCMLL_ASM -DECP_NISTZ256_ASM -DGHASH_ASM -DKECCAK1600_ASM \
	      -DMD5_ASM -DOPENSSL_BN_ASM_GF2m -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_CPUID_OBJ \
	      -DOPENSSL_IA32_SSE2 -DPOLY1305_ASM -DRC4_ASM -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DVPAES_ASM \
	      -DWHIRLPOOL_ASM -DX25519_ASM -fPIC -c $< -o $@

$(SRC_DIR)/_test_ptr/.@.tests.o: $(SRC_DIR)/_test_ptr/.@.tests.c
	$(CC) $(CFLAGS) $(INCLUDES) -fPIC -c $< -o $@

$(SRC_DIR)/_test_vprintf_stderr/.@.bioprinttest.o: $(SRC_DIR)/_test_vprintf_stderr/.@.bioprinttest.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(SRC_DIR)/_test_printf_stderr/.@.output.o: $(SRC_DIR)/_test_printf_stderr/.@.output.c
	$(CC) $(CFLAGS) $(INCLUDES) -fPIC -c $< -o $@

$(OUTPUT): $(BUILD_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(OPENSSL_DEFS) -ldl -L/StaticSlicer/test_lib/openssl/build_ss -lcrypto -lssl $^ -o $@

clean:
	rm -f $(BUILD_OBJS) $(OUTPUT)
