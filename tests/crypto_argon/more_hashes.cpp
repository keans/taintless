#include "t1ha.h"
#include "SpookyV2.h"
void g(const void *p, unsigned long n) {
    t1ha2_atonce(p, n, 0);
    SpookyHash::Hash64(p, n, 0);
}
