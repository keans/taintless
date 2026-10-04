import javax.crypto.Cipher;
import java.security.MessageDigest;

class Typed {
    static final String BASE = "MD5";
    static final String ALIAS = BASE;
    static final String ALIAS2 = ALIAS;

    // only the declared type says what `c` is
    byte[] seal(Cipher c, byte[] d) throws Exception {
        return c.doFinal(d);
    }

    // a caller passes a concrete cipher: that is the better report
    byte[] open(Cipher c, byte[] d) throws Exception {
        return c.doFinal(d);
    }

    void run(byte[] d) throws Exception {
        open(Cipher.getInstance("DES/ECB/PKCS5Padding"), d);
        MessageDigest.getInstance(ALIAS2);
    }
}

class Wrappers {
    static MessageDigest digest(String alg) throws Exception {
        return MessageDigest.getInstance(alg);
    }

    static MessageDigest other(String alg) throws Exception {
        return MessageDigest.getInstance(alg);
    }

    void run() throws Exception {
        digest("MD5");
        other("MD5");
        other("SHA-256");
    }
}
