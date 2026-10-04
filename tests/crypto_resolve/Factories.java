import javax.crypto.Cipher;
class DesFactory {
    static Cipher build() throws Exception { return Cipher.getInstance("DES/ECB/PKCS5Padding"); }
}
class AesFactory {
    static Cipher build() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); }
}
class Use {
    void f() throws Exception {
        Cipher a = DesFactory.build();
        a.init(1, null);
        Cipher b = AesFactory.build();
        b.init(1, null);
    }
}
