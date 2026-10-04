#include <farmhash.h>
void g(const char *pw, unsigned long n) {
    farmhash::Hash64(pw, n);
}
