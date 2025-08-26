# utilize modified FuzzSlice(StaticSlicer) to generate fuzzing targets for OpenSSL

export LLVM_COMPILER=clang

cd ./test_lib/openssl
git fetch
# checkout the corresponding commit ID before running the script on the certain target
git checkout 6637d7d
cp ./Configure ./configure

cd ../../

# target pattern: '/Path/to/your_target_file.c:target_line:*' , one target per run , comment out the targets below it
# Commit ID : 6637d7d (in openssl-3.3.1 on 240412)
printf '%s' './test_lib/openssl/test/cmp_hdr_test.c:141:    2024-57729' > ./info_lib/openssl/targets.txt
printf '%s' './test_lib/openssl/crypto/pkcs12/p12_crt.c:250:    2024-57731 -lm' > ./info_lib/openssl/targets.txt
printf '%s' './test_lib/openssl/ssl/statem/statem_srvr.c:3232:  2024-57735' > ./info_lib/openssl/targets.txt
printf '%s' './test_lib/openssl/ssl/quic/quic_trace.c:95:   2024-57736' > ./info_lib/openssl/targets.txt
printf '%s' './test_lib/openssl/apps/list.c:1234:   2024-57737' > ./info_lib/openssl/targets.txt
printf '%s' './test_lib/openssl/test/bad_dtls_test.c:491:   2024-57738' > ./info_lib/openssl/targets.txt
printf '%s' './test_lib/openssl/test/tls-provider.c:3226:   2024-57739 -lm' > ./info_lib/openssl/targets.txt
# printf '%s' './test_lib/openssl/crypto/provider_core.c:568: 2024-57740 error: unknown type name 'OSSL_PROVIDER_CHILD_CB'; did you mean 'OSSL_PROVIDER_INFO'?' > ./info_lib/openssl/targets.txt
printf '%s' './test_lib/openssl/crypto/x509/v3_addr.c:413:  2024-57741 -lm' > ./info_lib/openssl/targets.txt
printf '%s' './test_lib/openssl/test/v3ext.c:266:   2024-57742' > ./info_lib/openssl/targets.txt
printf '%s' './test_lib/openssl/test/threadpool_test.c:134: 2024-57743' > ./info_lib/openssl/targets.txt

# # Commit ID : 1f7d2a2 (in openssl-3.5.0 on 241113)
# printf '%s' './test_lib/openssl/providers/implementations/keymgmt/dsa_kmgmt.c:634:  2024-57730' > ./info_lib/openssl/targets.txt
# printf '%s' './test_lib/openssl/ssl/ssl_conf.c:678: 2024-57732' > ./info_lib/openssl/targets.txt
# printf '%s' './test_lib/openssl/crypto/x509/by_store.c:125: 2024-57733' > ./info_lib/openssl/targets.txt

# # Commit ID : f7ded92 (in openssl-3.5.0 on 240531)
# printf '%s' './test_lib/openssl/crypto/x509/x_ietfatt.c:178:    2024-57734' > ./info_lib/openssl/targets.txt

python3 main.py > ./info_lib/openssl/build.log 2>&1