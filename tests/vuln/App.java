class App {
    void handle(HttpServletRequest req, Statement st) throws Exception {
        String id = req.getParameter("id");
        st.executeQuery("SELECT * FROM t WHERE id=" + id);
        Runtime.getRuntime().exec("ls " + id);
        int n = Integer.parseInt(req.getParameter("n"));
        st.executeQuery("SELECT * FROM t LIMIT " + n);
        new FileInputStream(id);
    }
}
