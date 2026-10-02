class Runner {
    void run() {}
}

class Other {
    void run() {}
}

class Svc {
    private Runner r;

    void go() {
        this.r.run();
    }

    void local() {
        Runner x = make();
        x.run();
    }

    Object make() {
        return null;
    }
}
