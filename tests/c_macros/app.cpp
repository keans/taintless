#include <cstdlib>
#include "config.h"

#ifdef __cplusplus
int cpp_only(int argc, char **argv) {
    RUN(argv[1]);
    return 0;
}
#else
int c_only(int argc, char **argv) {
    RUN(argv[1]);
    return 0;
}
#endif

// the macro _WIN32 is not defined anywhere here: both branches are analyzed
#ifdef _WIN32
int windows(int argc, char **argv) {
    RUN(argv[1]);
    return 0;
}
#else
int posix(int argc, char **argv) {
    RUN(argv[1]);
    return 0;
}
#endif
