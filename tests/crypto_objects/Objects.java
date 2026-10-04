import javax.crypto.Cipher;

class Objects {
    void reassigned(byte[] x) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        c.doFinal(x);
        c = Cipher.getInstance("AES/GCM/NoPadding");
        c.doFinal(x);
    }

    void loop(byte[] x, boolean legacy) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        for (int i = 0; i < 2; i++) {
            c.doFinal(x);
            c = Cipher.getInstance("DES/CBC/PKCS5Padding");
        }
    }
}
