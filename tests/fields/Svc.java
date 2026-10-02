class Svc {
    private String cmd;
    private String name = "ls";

    void set(HttpServletRequest r) {
        this.cmd = r.getParameter("c");
    }

    void go() throws Exception {
        Runtime.getRuntime().exec(this.cmd);
        Runtime.getRuntime().exec(this.name);
    }
}
