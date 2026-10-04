import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;
class Keys {
    void f() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPairGenerator ok = KeyPairGenerator.getInstance("RSA");
        ok.initialize(3072);
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(64);
    }
}
