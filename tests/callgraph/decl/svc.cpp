struct Runner {
    void run() {}
};

struct Other {
    void run() {}
};

class Svc {
    std::shared_ptr<Runner> r;

    void go_() {
        r.run();
    }

    void local() {
        Runner x;
        x.run();
    }
};
