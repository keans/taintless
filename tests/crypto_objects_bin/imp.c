extern void *EVP_md5(void);
extern int EVP_DigestInit_ex(void *, void *, void *);
int main(void) {
    EVP_DigestInit_ex(0, EVP_md5(), 0);
    return 0;
}
