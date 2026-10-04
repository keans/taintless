#include <openssl/evp.h>
#include <mbedtls/md5.h>
void f() {
    const EVP_MD *a = EVP_md5();
    const EVP_MD *b = EVP_sha256();
    EVP_CIPHER_CTX_new();
    EVP_aes_128_ecb();
    mbedtls_md5_starts(0);
    mbedtls_sha256_starts(0, 0);
}
