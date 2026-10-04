import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;
class App {
    void f(HttpServletRequest req) throws Exception {
        String t = req.getParameter("transformation");
        Cipher.getInstance(t);
        Cipher.getInstance("AES/GCM/NoPadding");
    }
}
