# 编译器
CC ?= wllvm

# 文件路径
SRC := /StaticSlicer/workspace/openssl/test_files/266.@.v3ext.c
OBJ := /StaticSlicer/workspace/openssl/test_files/266.@.v3ext.o
OBJ_TEST1 := /StaticSlicer/workspace/openssl/test_files/266.@.v3ext/_test_ptr/.@.tests.o
OBJ_TEST2 := /StaticSlicer/workspace/openssl/test_files/266.@.v3ext/_test_flush_stderr/.@.bioprinttest.o
OBJ_TEST3 := /StaticSlicer/workspace/openssl/test_files/266.@.v3ext/_test_printf_stderr/.@.output.o
OUT := /StaticSlicer/workspace/openssl/test_files/266.@.v3ext.out

# 头文件路径
INCLUDES := \
  -I/StaticSlicer/test_lib/openssl/build_ss/include \
  -I/StaticSlicer/test_lib/openssl/build_ss/apps/include \
  -I/StaticSlicer/test_lib/openssl/build_ss \
  -I/StaticSlicer/test_lib/openssl/include \
  -I/StaticSlicer/test_lib/openssl/apps/include \
  -I/StaticSlicer/test_lib/openssl

# 宏定义
DEFINES := \
  -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC \
  -DOPENSSLDIR="/usr/local/ssl" \
  -DENGINESDIR="/usr/local/lib64/engines-3" \
  -DMODULESDIR="/usr/local/lib64/ossl-modules" \
  -DOPENSSL_BUILDING_OPENSSL -DNDEBUG

# 编译与链接参数
CFLAGS := -fPIC -pthread -m64 -Wa,--noexecstack -Qunused-arguments -Wall -O0 -w
LDFLAGS := -ldl -L/StaticSlicer/test_lib/openssl/build_ss -lcrypto -lssl

# 默认目标
all: $(OUT)

# 主源码编译
$(OBJ): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

# 附加测试文件编译
$(OBJ_TEST1): /StaticSlicer/workspace/openssl/test_files/266.@.v3ext/_test_ptr/.@.tests.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

$(OBJ_TEST2): /StaticSlicer/workspace/openssl/test_files/266.@.v3ext/_test_flush_stderr/.@.bioprinttest.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

$(OBJ_TEST3): /StaticSlicer/workspace/openssl/test_files/266.@.v3ext/_test_printf_stderr/.@.output.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@

# 链接目标文件
$(OUT): $(OBJ) $(OBJ_TEST1) $(OBJ_TEST2) $(OBJ_TEST3)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) $(LDFLAGS) $^ -o $@

# 清理目标
clean:
	rm -f $(OBJ) $(OBJ_TEST1) $(OBJ_TEST2) $(OBJ_TEST3) $(OUT)
