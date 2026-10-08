#include <stdio.h>
#include <stdlib.h>
#include "config.h"

#define ARG1 argv[1]
#define LAUNCH(a, b) a##b

/* a function-like macro from the header that calls system() */
int via_header_macro(int argc, char **argv) {
    char *c = ARG1;
    RUN(c);
    return 0;
}

/* an object-like macro from the header that names system */
int via_header_alias(int argc, char **argv) {
    SHELL_EXEC(FIRST_ARG(argv));
    return 0;
}

/* token pasting builds the callee name */
int via_paste(int argc, char **argv) {
    LAUNCH(sys, tem)(argv[1]);
    return 0;
}

#if MODE == 2
int selected(int argc, char **argv) {
    system(argv[1]);
    return 0;
}
#else
int dropped(int argc, char **argv) {
    system(argv[1]);
    return 0;
}
#endif

#if 0
int disabled(int argc, char **argv) {
    system(argv[1]);
    return 0;
}
#endif

/* a literal command is fine */
int safe(void) {
    RUN("ls");
    return 0;
}
