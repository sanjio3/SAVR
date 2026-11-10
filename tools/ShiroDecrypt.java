import org.apache.shiro.crypto.AesCipherService;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/** Reads a base64 cookie value on stdin, decrypts it with Shiro, prints the raw bytes. */
public class ShiroDecrypt {
    public static void main(String[] args) throws Exception {
        byte[] key = Base64.getDecoder().decode(args[0]);
        BufferedReaderShim br = new BufferedReaderShim();
        String line = br.readLine();
        byte[] cookie = Base64.getDecoder().decode(line.trim());
        AesCipherService acs = new AesCipherService();
        try {
            byte[] plain = acs.decrypt(cookie, key).getBytes();
            System.out.println("DECRYPT_OK len=" + plain.length + " head="
                    + hex(plain, 4));
            System.out.println("BASE64=" + Base64.getEncoder().encodeToString(plain));
        } catch (Exception e) {
            System.out.println("DECRYPT_FAIL " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    static String hex(byte[] b, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(n, b.length); i++) {
            sb.append(String.format("%02x", b[i]));
        }
        return sb.toString();
    }

    static class BufferedReaderShim {
        private final java.io.BufferedReader r =
                new java.io.BufferedReader(new java.io.InputStreamReader(System.in));

        String readLine() throws Exception {
            return r.readLine();
        }
    }
}
