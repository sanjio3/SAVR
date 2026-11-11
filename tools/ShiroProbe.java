import org.apache.shiro.crypto.AesCipherService;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class ShiroProbe {
    static byte[] raw = new byte[64];

    public static void main(String[] args) throws Exception {
        byte[] key = Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
        new SecureRandom().nextBytes(raw);
        raw[0] = (byte) 0xac; raw[1] = (byte) 0xed; raw[2] = 0; raw[3] = 5;

        AesCipherService acs = new AesCipherService();
        System.out.println("generateInitializationVectors = " + acs.isGenerateInitializationVectors());
        System.out.println("initializationVectorSize(bits) = " + acs.getInitializationVectorSize());
        System.out.println("modeName = " + acs.getModeName());
        System.out.println("paddingScheme = " + acs.getPaddingSchemeName());

        Cipher c1 = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c1.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] enc1 = c1.doFinal(raw);
        System.out.println("form1 (ciphertext only) len=" + enc1.length);
        try {
            byte[] d1 = acs.decrypt(enc1, key).getBytes();
            System.out.println("  form1 decrypt OK, matches=" + java.util.Arrays.equals(d1, raw));
        } catch (Exception e) {
            System.out.println("  form1 decrypt FAIL: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        byte[] iv = new byte[acs.getInitializationVectorSize() / 8];
        new SecureRandom().nextBytes(iv);
        Cipher c2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c2.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] enc2 = c2.doFinal(raw);
        byte[] both = new byte[iv.length + enc2.length];
        System.arraycopy(iv, 0, both, 0, iv.length);
        System.arraycopy(enc2, 0, both, iv.length, enc2.length);
        System.out.println("form2 (iv||ciphertext) len=" + both.length);
        try {
            byte[] d2 = acs.decrypt(both, key).getBytes();
            System.out.println("  form2 decrypt OK, matches=" + java.util.Arrays.equals(d2, raw));
        } catch (Exception e) {
            System.out.println("  form2 decrypt FAIL: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
