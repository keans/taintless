class Bare {
    private String cmd;
    private String safe = "ls";

    void set(HttpServletRequest r) {
        cmd = r.getParameter("c");
    }

    void go() throws Exception {
        Runtime.getRuntime().exec(cmd);
        Runtime.getRuntime().exec(safe);
    }

    void shadow(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
