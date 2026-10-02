class Res {
    void run(java.util.List<String> xs) throws Exception {
        try (java.io.Reader r = open(); java.io.Reader q = open()) {
            r.read();
        } catch (java.io.IOException e) {
            log(e);
        }
        Runnable job = () -> { if (xs.isEmpty()) { return; } work(); };
        xs.forEach(x -> use(x));
    }
}
