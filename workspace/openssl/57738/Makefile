# ========================
# Configurable Parameters
# ========================

CC ?= wllvm
SRC_DIR := /StaticSlicer/workspace/openssl/test_files/491.@.bad_dtls_test
SRC := $(SRC_DIR).c
OBJ := $(SRC:.c=.o)
OUT := $(SRC_DIR).out

EXTRA_OBJS := \
  $(SRC_DIR)/_test_ptr/.@.tests.o \
  $(SRC_DIR)/_test_flush_stderr/.@.bioprinttest.o \
  $(SRC_DIR)/_test_printf_stderr/.@.output.o

INCLUDES := \
  -I/StaticSlicer/test_lib/openssl/build_ss/include \
  -I/StaticSlicer/test_lib/openssl/build_ss/apps/include \
  -I/StaticSlicer/test_lib/openssl/build_ss \
  -I/StaticSlicer/test_lib/openssl/include \
  -I/StaticSlicer/test_lib/openssl/apps/include \
  -I/StaticSlicer/test_lib/openssl

DEFINES := \
  -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC \
  -DOPENSSLDIR=\"/usr/local/ssl\" \
  -DENGINESDIR=\"/usr/local/lib64/engines-3\" \
  -DMODULESDIR=\"/usr/local/lib64/ossl-modules\" \
  -DOPENSSL_BUILDING_OPENSSL -DNDEBUG

CFLAGS := -fPIC -pthread -m64 -Wa,--noexecstack -Qunused-arguments -Wall -O0 -w
LDFLAGS := -ldl -L/StaticSlicer/test_lib/openssl/build_ss -lcrypto -lssl

# ========================
# Build Rules
# ========================

all: $(OUT)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

$(SRC_DIR)/_test_ptr/%.o: $(SRC_DIR)/_test_ptr/%.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

$(SRC_DIR)/_test_flush_stderr/%.o: $(SRC_DIR)/_test_flush_stderr/%.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

$(SRC_DIR)/_test_printf_stderr/%.o: $(SRC_DIR)/_test_printf_stderr/%.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

$(OUT): $(OBJ) $(EXTRA_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) $(LDFLAGS) $^ -o $@

clean:
	rm -f $(OBJ) $(EXTRA_OBJS) $(OUT)
