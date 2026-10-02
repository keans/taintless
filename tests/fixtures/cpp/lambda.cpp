int g(int a) {
    auto h = [](int x) { if (x > 0) { return 1; } return 2; };
    return h(a);
}
