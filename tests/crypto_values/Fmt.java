import java.security.MessageDigest;

class Fmt {
    void run(String other) throws Exception {
        MessageDigest.getInstance(String.format("SHA-%d", 1));
        MessageDigest.getInstance(String.format("SHA-%d", 256));
        MessageDigest.getInstance(String.format("MD%s", other));
    }
}
