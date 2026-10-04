import java.security.MessageDigest;

class Spec {
    void run() throws Exception {
        MessageDigest.getInstance(String.format("MD%1d", 5));
        MessageDigest.getInstance(String.format("SHA-%03d", 1));
    }
}
