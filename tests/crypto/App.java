import javax.crypto.Cipher;
import java.security.MessageDigest;
class App {
    void f() throws Exception {
        Cipher.getInstance("AES/CBC/PKCS5Padding");
        Cipher.getInstance("AES");
        MessageDigest.getInstance("SHA-256");
        MessageDigest.getInstance("MD5");
    }
}
