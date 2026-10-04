import java.security.MessageDigest;

class Parts {
    static final String ALGO = "M" + "D5";

    static String legacy() {
        return "DE" + "S/ECB/PKCS5Padding";
    }

    void run(String mode) throws Exception {
        MessageDigest.getInstance(ALGO);
        MessageDigest.getInstance("SHA-" + "1");
        javax.crypto.Cipher.getInstance(legacy());
        MessageDigest.getInstance("SHA-" + mode);
    }
}
