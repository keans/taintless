import com.google.common.hash.Hashing;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
class Hashes {
    void f(byte[] d) {
        Hashing.sipHash24();
        Hashing.murmur3_128();
        Hashing.sha256();
        new Argon2PasswordEncoder(16, 32, 1, 4096, 3);
        new Argon2PasswordEncoder(16, 32, 1, 65536, 3);
    }
}
