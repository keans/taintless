class Expr {
    String s(int k) {
        return switch (k) { case 1, 2 -> "low"; default -> "high"; };
    }
    int t(boolean a) { return a ? 1 : 2; }
    void r() throws Exception {
        try (var r = open()) {
            if (check()) { return; }
            use(r);
        } catch (Exception e) {
            log(e);
        }
    }
    void f() { try { work(); } finally { done(); } }
}
