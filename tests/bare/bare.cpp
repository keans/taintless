class Bare {
    std::string cmd;
    std::string safe;
public:
    void set() {
        cmd = getenv("C");
    }
    void go() {
        system(cmd.c_str());
        system(safe.c_str());
    }
    void shadow(const char *cmd) {
        system(cmd);
    }
};
