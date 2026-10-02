int r(int x) {
    switch (x) {
    case 1 ... 5:
        return 1;
    default:
        return 0;
    }
}

int q(int a, int b) {
    int v = a ? b : 0;
    return a && b;
}
