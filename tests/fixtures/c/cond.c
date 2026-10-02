int c(int a, int b) {
    if (!a && b) return 1;
    while (a || b) { a--; }
    return 0;
}
