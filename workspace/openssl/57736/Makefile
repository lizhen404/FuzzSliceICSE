# Makefile for building quic_trace target

# Customize compiler: default wllvm, can override with environment variable
CC ?= wllvm

# Common compile flags
CFLAGS = -I/StaticSlicer/test_lib/openssl/build_ss/include \
         -I/StaticSlicer/test_lib/openssl/build_ss/apps/include \
         -I/StaticSlicer/test_lib/openssl/include \
         -I/StaticSlicer/test_lib/openssl/apps/include \
         -pthread -m64 -Wa,--noexecstack -Qunused-arguments -Wall \
         -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -O0 -w -fPIC

# Link flags and libs
LDFLAGS = -ldl \
          -L/StaticSlicer/test_lib/openssl/build_ss \
          -lcrypto -lssl \
          -pthread -m64 -Wa,--noexecstack -Qunused-arguments -Wall \
          -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -w

# Source and object files
SRC = /StaticSlicer/workspace/openssl/test_files/95.@.quic_trace.c \
      /StaticSlicer/workspace/openssl/test_files/95.@.quic_trace/_ossl_quic_wire_decode_frame_ack/.@.quic_wire.c \
      /StaticSlicer/workspace/openssl/test_files/95.@.quic_trace/_ossl_quic_vlint_decode_unchecked/.@.quic_vlint.c

OBJ = /StaticSlicer/workspace/openssl/test_files/95.@.quic_trace.o \
      /StaticSlicer/workspace/openssl/test_files/95.@.quic_trace/_ossl_quic_wire_decode_frame_ack/.@.quic_wire.o \
      /StaticSlicer/workspace/openssl/test_files/95.@.quic_trace/_ossl_quic_vlint_decode_unchecked/.@.quic_vlint.o

# Target executable
TARGET = /StaticSlicer/workspace/openssl/test_files/95.@.quic_trace.out

.PHONY: all clean

all: $(TARGET)

# Compile source files to objects
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Link objects to final executable
$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f $(OBJ) $(TARGET)
