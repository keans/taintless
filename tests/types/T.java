class Runner {
    void go(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}

class Safe {
    void go(String cmd) {
        System.out.println(cmd);
    }
}

class Use {
    static Runner make() {
        return new Runner();
    }

    void viaFactory() throws Exception {
        Runner r = Use.make();
        r.go(System.getenv("C"));
    }

    void viaParam(Runner r, Safe s) throws Exception {
        r.go(System.getenv("C"));
        s.go(System.getenv("C"));
    }
}
