#include <stdio.h>

int run(int *xs, int n, int mode) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        if (xs[i] < 0) continue;
        if (xs[i] > 100) break;
        total += xs[i];
    }
    while (total > 10) total -= 10;
    do { total++; } while (total < 5);
    switch (mode) {
    case 1:
        total += 1;
    case 2:
        total += 2;
        break;
    default:
        return -1;
    }
    if (total == 7) goto done;
    total *= 2;
done:
    printf("%d\n", total);
    return total;
}

static void spin(void) { for (;;) { } }
