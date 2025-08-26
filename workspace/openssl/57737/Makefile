# Makefile for building list target

CC ?= wllvm

CFLAGS = -I/StaticSlicer/test_lib/openssl/build_ss/apps \
         -I/StaticSlicer/test_lib/openssl/build_ss \
         -I/StaticSlicer/test_lib/openssl/build_ss/include \
         -I/StaticSlicer/test_lib/openssl/build_ss/apps/include \
         -I/StaticSlicer/test_lib/openssl \
         -I/StaticSlicer/test_lib/openssl/include \
         -I/StaticSlicer/test_lib/openssl/apps/include \
         -pthread -m64 -Wa,--noexecstack -Qunused-arguments -Wall \
         -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -O0 -w

LDFLAGS = -ldl \
          -L/StaticSlicer/test_lib/openssl/build_ss \
          -lcrypto -lssl \
          -I/StaticSlicer/test_lib/openssl/build_ss/apps \
          -I/StaticSlicer/test_lib/openssl/build_ss \
          -I/StaticSlicer/test_lib/openssl/build_ss/include \
          -I/StaticSlicer/test_lib/openssl/build_ss/apps/include \
          -I/StaticSlicer/test_lib/openssl \
          -I/StaticSlicer/test_lib/openssl/include \
          -I/StaticSlicer/test_lib/openssl/apps/include \
          -pthread -m64 -Wa,--noexecstack -Qunused-arguments -Wall \
          -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -w

SRC = /StaticSlicer/workspace/openssl/test_files/1234.@.list.c \
      /StaticSlicer/workspace/openssl/test_files/1234.@.list/bio_err/.@.openssl.c

OBJ = /StaticSlicer/workspace/openssl/test_files/1234.@.list.o \
      /StaticSlicer/workspace/openssl/test_files/1234.@.list/bio_err/.@.openssl.o

TARGET = /StaticSlicer/workspace/openssl/test_files/1234.@.list.out

.PHONY: all clean

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f $(OBJ) $(TARGET)
