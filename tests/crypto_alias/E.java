import java.security.MessageDigest;
import static java.security.MessageDigest.getInstance;
class E { void f() throws Exception { MessageDigest.getInstance("MD5"); getInstance("SHA-1"); } }
