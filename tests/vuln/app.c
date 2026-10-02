int main(int argc, char **argv) {
    char buf[64];
    char *name = getenv("NAME");
    system(name);
    strcpy(buf, argv[1]);
    printf(argv[1]);
    printf("%s", argv[1]);
    int n = atoi(argv[2]);
    char *p = malloc(n);
    gets(buf);
    return 0;
}
