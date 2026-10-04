import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.jasypt.util.text.BasicTextEncryptor;
import org.apache.commons.codec.digest.DigestUtils;
class Spring {
    void f(String pw) {
        new BCryptPasswordEncoder(4);
        new StandardPasswordEncoder("secret");
        new BasicTextEncryptor();
        DigestUtils.sha1Hex(pw);
        DigestUtils.sha256Hex(pw);
    }
}
