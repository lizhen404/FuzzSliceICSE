# Makefile for compiling the project based on the build log.
#
# Usage:
#   make          - Compiles the project with the default compiler (wllvm).
#   make CC=clang - Compiles the project using clang as the compiler.
#   make CC=gcc   - Compiles the project using gcc as the compiler.
#   make clean    - Removes all generated object files and the final executable.

.PHONY: all clean

# ----------------- Configuration -----------------

# Compiler: Can be overridden from the command line.
# e.g., `make CC=clang`
CC ?= wllvm

# Base directories
BASE_DIR       := /StaticSlicer
WORKSPACE_DIR  := $(BASE_DIR)/workspace/openssl
TEST_LIB_DIR   := $(BASE_DIR)/test_lib/openssl
TEST_FILES_DIR := $(WORKSPACE_DIR)/test_files/134.@.threadpool_test

# Final executable target
TARGET := $(TEST_FILES_DIR).out

# ----------------- Object Files -----------------

# List of all object files to be linked.
OBJS := \
	$(TEST_FILES_DIR).o \
	$(TEST_FILES_DIR)/_ossl_crypto_thread_start/.@.internal.o \
	$(TEST_FILES_DIR)/_test_ptr_null/.@.tests.o \
	$(TEST_FILES_DIR)/_ossl_lib_ctx_get_data/.@.context.o \
	$(TEST_FILES_DIR)/_ossl_crypto_thread_native_start/.@.arch.o \
	$(TEST_FILES_DIR)/_ossl_crypto_mutex_lock/.@.thread_posix.o \
	$(TEST_FILES_DIR)/_test_vprintf_stderr/.@.bioprinttest.o \
	$(TEST_FILES_DIR)/_test_printf_stderr/.@.output.o \
	$(TEST_FILES_DIR)/_ossl_bio_core_globals_new/.@.bss_core.o \
	$(TEST_FILES_DIR)/_ossl_stored_namemap_new/.@.core_namemap.o \
	$(TEST_FILES_DIR)/_ossl_decoder_cache_new/.@.decoder_pkey.o \
	$(TEST_FILES_DIR)/_ossl_crypto_cleanup_all_ex_data_int/.@.ex_data.o \
	$(TEST_FILES_DIR)/_ossl_property_defns_new/.@.defn_cache.o \
	$(TEST_FILES_DIR)/_ossl_ctx_global_properties_new/.@.property.o \
	$(TEST_FILES_DIR)/_ossl_property_parse_init/.@.property_parse.o \
	$(TEST_FILES_DIR)/_ossl_property_string_data_free/.@.property_string.o \
	$(TEST_FILES_DIR)/_ossl_child_prov_ctx_new/.@.provider_child.o \
	$(TEST_FILES_DIR)/_ossl_prov_conf_ctx_new/.@.provider_conf.o \
	$(TEST_FILES_DIR)/_ossl_provider_store_free/.@.provider_core.o \
	$(TEST_FILES_DIR)/_ossl_rand_ctx_new/.@.rand_lib.o \
	$(TEST_FILES_DIR)/_ossl_self_test_set_callback_free/.@.self_test_core.o \
	$(TEST_FILES_DIR)/_ossl_rand_crng_ctx_new/.@.crngt.o \
	$(TEST_FILES_DIR)/_ossl_prov_drbg_nonce_ctx_free/.@.drbg.o \
	$(TEST_FILES_DIR)/_ossl_decoder_store_remove_all_provided/.@.decoder_meth.o \
	$(TEST_FILES_DIR)/_ossl_encoder_store_remove_all_provided/.@.encoder_meth.o \
	$(TEST_FILES_DIR)/_evp_method_store_remove_all_provided/.@.evp_fetch.o \
	$(TEST_FILES_DIR)/_ossl_init_thread_deregister/.@.initthread.o \
	$(TEST_FILES_DIR)/_ossl_lh_strcasehash/.@.lhash.o \
	$(TEST_FILES_DIR)/_ossl_sa_doall_arg/.@.sparse_array.o \
	$(TEST_FILES_DIR)/_ossl_store_loader_store_remove_all_provided/.@.store_meth.o

# ----------------- Compiler and Linker Flags -----------------

# Common include paths
INCLUDE_PATHS_COMMON := \
	-I$(TEST_LIB_DIR)/build_ss \
	-I$(TEST_LIB_DIR)/build_ss/include \
	-I$(TEST_LIB_DIR) \
	-I$(TEST_LIB_DIR)/include

# Include paths for 'apps'
INCLUDE_PATHS_APPS := \
	-I$(TEST_LIB_DIR)/build_ss/apps/include \
	-I$(TEST_LIB_DIR)/apps/include

# Include paths for 'providers'
INCLUDE_PATHS_PROVIDERS := \
	-I$(TEST_LIB_DIR)/build_ss/providers/common/include \
	-I$(TEST_LIB_DIR)/build_ss/providers/implementations/include \
	-I$(TEST_LIB_DIR)/providers/common/include \
	-I$(TEST_LIB_DIR)/providers/implementations/include

# Include paths for 'crypto'
INCLUDE_PATHS_CRYPTO := \
	-I$(TEST_LIB_DIR)/build_ss/crypto \
	-I$(TEST_LIB_DIR)/crypto

# Common compiler flags
COMMON_FLAGS := \
	-pthread -m64 -Wa,--noexecstack -Qunused-arguments \
	-Wall -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -O0 -w

# Flags for PIC (Position-Independent Code) and specific OpenSSL defines
PIC_FLAGS := \
	-fPIC -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC \
	-DOPENSSLDIR="/usr/local/ssl" \
	-DENGINESDIR="/usr/local/lib64/engines-3" \
	-DMODULESDIR="/usr/local/lib64/ossl-modules"

# ASM-related defines
ASM_DEFINES_FULL := \
	-DAES_ASM -DBSAES_ASM -DCMLL_ASM -DECP_NISTZ256_ASM -DGHASH_ASM \
	-DKECCAK1600_ASM -DMD5_ASM -DOPENSSL_BN_ASM_GF2m -DOPENSSL_BN_ASM_MONT \
	-DOPENSSL_BN_ASM_MONT5 -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 \
	-DPOLY1305_ASM -DRC4_ASM -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM \
	-DVPAES_ASM -DWHIRLPOOL_ASM -DX25519_ASM

ASM_DEFINES_PARTIAL := \
	-DAES_ASM -DBSAES_ASM -DECP_NISTZ256_ASM -DKECCAK1600_ASM \
	-DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DSHA1_ASM -DSHA256_ASM \
	-DSHA512_ASM -DVPAES_ASM -DX25519_ASM

# Combine flags for different types of source files
CFLAGS_TYPE_A := $(INCLUDE_PATHS_COMMON) $(INCLUDE_PATHS_APPS) $(COMMON_FLAGS)
CFLAGS_TYPE_B := $(INCLUDE_PATHS_COMMON) $(INCLUDE_PATHS_APPS) $(PIC_FLAGS) $(COMMON_FLAGS)
CFLAGS_TYPE_C := $(INCLUDE_PATHS_COMMON) $(INCLUDE_PATHS_PROVIDERS) $(PIC_FLAGS) $(ASM_DEFINES_FULL) $(COMMON_FLAGS)
CFLAGS_TYPE_D := $(INCLUDE_PATHS_COMMON) $(INCLUDE_PATHS_PROVIDERS) $(INCLUDE_PATHS_CRYPTO) $(PIC_FLAGS) $(ASM_DEFINES_PARTIAL) $(COMMON_FLAGS)

# Linker flags and libraries
LDFLAGS :=
LIBS := -ldl -L$(TEST_LIB_DIR)/build_ss -lcrypto -lssl

# ----------------- Build Rules -----------------

# Default target
all: $(TARGET)

# Rule to link the final executable
$(TARGET): $(OBJS)
	@echo "--- Linking executable: $(TARGET) ---"
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

# --- Compilation Rules for each object file ---

# Group 1: Using CFLAGS_TYPE_A
$(TEST_FILES_DIR).o: $(TEST_FILES_DIR).c
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS_TYPE_A) -c $< -o $@

$(TEST_FILES_DIR)/_test_vprintf_stderr/.@.bioprinttest.o: $(TEST_FILES_DIR)/_test_vprintf_stderr/.@.bioprinttest.c
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS_TYPE_A) -c $< -o $@

# Group 2: Using CFLAGS_TYPE_B
$(TEST_FILES_DIR)/_test_ptr_null/.@.tests.o: $(TEST_FILES_DIR)/_test_ptr_null/.@.tests.c
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS_TYPE_B) -c $< -o $@

$(TEST_FILES_DIR)/_test_printf_stderr/.@.output.o: $(TEST_FILES_DIR)/_test_printf_stderr/.@.output.c
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS_TYPE_B) -c $< -o $@

# Group 3: Using CFLAGS_TYPE_C
$(TEST_FILES_DIR)/_ossl_crypto_thread_start/.@.internal.o: $(TEST_FILES_DIR)/_ossl_crypto_thread_start/.@.internal.c
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS_TYPE_C) -c $< -o $@

# All other files in this group also use CFLAGS_TYPE_C
$(TEST_FILES_DIR)/_ossl_lib_ctx_get_data/.@.context.o:           CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_crypto_thread_native_start/.@.arch.o:   CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_crypto_mutex_lock/.@.thread_posix.o:     CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_bio_core_globals_new/.@.bss_core.o:      CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_stored_namemap_new/.@.core_namemap.o:    CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_decoder_cache_new/.@.decoder_pkey.o:     CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_crypto_cleanup_all_ex_data_int/.@.ex_data.o: CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_property_defns_new/.@.defn_cache.o:      CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_ctx_global_properties_new/.@.property.o: CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_property_parse_init/.@.property_parse.o: CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_property_string_data_free/.@.property_string.o: CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_child_prov_ctx_new/.@.provider_child.o:  CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_prov_conf_ctx_new/.@.provider_conf.o:    CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_provider_store_free/.@.provider_core.o:  CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_rand_ctx_new/.@.rand_lib.o:               CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_self_test_set_callback_free/.@.self_test_core.o: CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_decoder_store_remove_all_provided/.@.decoder_meth.o: CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_encoder_store_remove_all_provided/.@.encoder_meth.o: CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_evp_method_store_remove_all_provided/.@.evp_fetch.o: CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_init_thread_deregister/.@.initthread.o:  CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_lh_strcasehash/.@.lhash.o:                CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_sa_doall_arg/.@.sparse_array.o:           CFLAGS := $(CFLAGS_TYPE_C)
$(TEST_FILES_DIR)/_ossl_store_loader_store_remove_all_provided/.@.store_meth.o: CFLAGS := $(CFLAGS_TYPE_C)

# Pattern rule for all files using CFLAGS_TYPE_C
$(TEST_FILES_DIR)/%/.@.%.o: $(TEST_FILES_DIR)/%/.@.%.c
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS) -c $< -o $@

# Group 4: Using CFLAGS_TYPE_D
$(TEST_FILES_DIR)/_ossl_rand_crng_ctx_new/.@.crngt.o: $(TEST_FILES_DIR)/_ossl_rand_crng_ctx_new/.@.crngt.c
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS_TYPE_D) -c $< -o $@

$(TEST_FILES_DIR)/_ossl_prov_drbg_nonce_ctx_free/.@.drbg.o: $(TEST_FILES_DIR)/_ossl_prov_drbg_nonce_ctx_free/.@.drbg.c
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS_TYPE_D) -c $< -o $@


# ----------------- Cleanup Rule -----------------

clean:
	@echo "--- Cleaning up generated files ---"
	rm -f $(TARGET) $(OBJS)