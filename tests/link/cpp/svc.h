struct Runner {
    void run();
};

struct Other {
    void run();
};

using R = Runner;
typedef Runner T;

class Svc {
    std::shared_ptr<Runner> r;
    R r2;
    T r3;

    void viaField();
    void viaAlias();
    void viaTypedef();
};
