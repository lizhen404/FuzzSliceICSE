# ========================
# Configurable Parameters
# ========================

CC ?= wllvm
SRC := /StaticSlicer/workspace/openssl/test_files/3226.@.tls-provider.c
OBJ := /StaticSlicer/workspace/openssl/test_files/3226.@.tls-provider.o
OUT := /StaticSlicer/workspace/openssl/test_files/3226.@.tls-provider.out

INCLUDES := \
  -I/StaticSlicer/test_lib/openssl/build_ss/include \
  -I/StaticSlicer/test_lib/openssl/build_ss/apps/include \
  -I/StaticSlicer/test_lib/openssl/build_ss \
  -I/StaticSlicer/test_lib/openssl/include \
  -I/StaticSlicer/test_lib/openssl/apps/include \
  -I/StaticSlicer/test_lib/openssl

DEFINES := \
  -DOPENSSL_BUILDING_OPENSSL -DNDEBUG

CFLAGS := -pthread -m64 -Wa,--noexecstack -Qunused-arguments -Wall -O0 -w
LDFLAGS := -lm -ldl -L/StaticSlicer/test_lib/openssl/build_ss -lcrypto -lssl

# ========================
# Build Rules
# ========================

all: $(OUT)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

$(OUT): $(OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) $(LDFLAGS) $^ -o $@

clean:
	rm -f $(OBJ) $(OUT)
