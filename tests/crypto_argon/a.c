#include <sodium.h>
void f(unsigned char *out, const char *pw, unsigned long n) {
    crypto_pwhash_str(out, pw, n, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
    crypto_pwhash_str(out, pw, n, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN);
    crypto_pwhash_str(out, pw, n, 2, 8 * 1024);
    CityHash64(pw, n);
}
