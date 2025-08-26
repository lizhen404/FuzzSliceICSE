# ========================
# Configurable Parameters
# ========================

CC ?= wllvm
SRC_DIR := /StaticSlicer/workspace/openssl/2024-57735/3232.@.statem_srvr
SRC := $(SRC_DIR).c
OBJ := $(SRC:.c=.o)
BUILD_DIR ?= .
# OUT := $(SRC_DIR).out
OUT := $(BUILD_DIR)/$(notdir $(SRC_DIR)).out

EXTRA_OBJS := \
  $(SRC_DIR)/_ossl_statem_fatal/.@.statem.o \
  $(SRC_DIR)/_ssl3_send_alert/.@.s3_msg.o \
  $(SRC_DIR)/_RECORD_LAYER_write_pending/.@.rec_layer_s3.o \
  $(SRC_DIR)/_tls13_alert_code/.@.tls13_enc.o \
  $(SRC_DIR)/_tls1_alert_code/.@.t1_enc.o

INCLUDES := \
  -I/StaticSlicer/test_lib/openssl/build_ss \
  -I/StaticSlicer/test_lib/openssl/build_ss/include \
  -I/StaticSlicer/test_lib/openssl \
  -I/StaticSlicer/test_lib/openssl/include

DEFINES := \
  -DAES_ASM -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC \
  -DOPENSSLDIR=\"/usr/local/ssl\" \
  -DENGINESDIR=\"/usr/local/lib64/engines-3\" \
  -DMODULESDIR=\"/usr/local/lib64/ossl-modules\" \
  -DOPENSSL_BUILDING_OPENSSL -DNDEBUG

CFLAGS_EXTRA ?=
CFLAGS := -fPIC -pthread -m64 -Wa,--noexecstack -Qunused-arguments -Wall -O0 -w -g $(CFLAGS_EXTRA)
LDFLAGS := -ldl -L/StaticSlicer/test_lib/openssl/build_ss -lcrypto -lssl

# ========================
# Build Rules
# ========================

all: $(OUT)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

$(OUT): $(OBJ) $(EXTRA_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) $(LDFLAGS) $^ -o $@

clean:
	rm -f $(OBJ) $(EXTRA_OBJS) $(OUT)
