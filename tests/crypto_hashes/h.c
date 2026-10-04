#include <argon2.h>
#include <sodium.h>
void f() {
    XXH64(buf, 8, 0);
    argon2id_hash_raw(2, 4096, 1, pwd, 8, salt, 16, out, 32);
    argon2id_hash_raw(2, 65536, 1, pwd, 8, salt, 16, out, 32);
    crypto_shorthash(out, in, 8, key);
}
