import javax.crypto.Cipher;
class Const {
    static final String ALGO = "AES/ECB/PKCS5Padding";
    void f(byte[] d) throws Exception {
        Cipher c = Cipher.getInstance(ALGO);
        c.init(1, null);
        c.doFinal(d);
    }
}
