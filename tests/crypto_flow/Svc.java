import javax.crypto.Cipher;
class Svc {
    static Cipher newCipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
    byte[] seal(Cipher c, byte[] d) throws Exception {
        return c.doFinal(d);
    }
    void run(byte[] d) throws Exception {
        Cipher c = newCipher();
        c.init(1, null);
        seal(c, d);
    }
}
