import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;
import static java.nio.charset.StandardCharsets.UTF_8;

//Demonstrate asymmetric encryption and decryption of message sent between Alice and Bob
//Use RSA-2048 encryption
public class RSA2048 {
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        return pair;
    }

    public static String encryptMessage(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decryptMessage(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static String signing(String plainText, PrivateKey privateKey) throws Exception {
        Signature signin = Signature.getInstance("SHA256withRSA");
        signin.initSign(privateKey);
        signin.update(plainText.getBytes(UTF_8));
        byte[] signature = signin.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean validating(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(plainText.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return sig.verify(signatureBytes);
    }

    public static void main(String... argv) throws Exception {
        KeyPair pair = generateKeyPair();
        String Alicemessage = "coding is happy";
        String cipherText = encryptMessage(Alicemessage, pair.getPublic());
        String BobMessage = decryptMessage(cipherText, pair.getPrivate());
        System.out.println("Alice message: " + Alicemessage);
        System.out.println("Bob message: " + BobMessage);
        String signature = signing("foobar", pair.getPrivate());
        boolean isCorrect = validating("foobar", signature, pair.getPublic());
        System.out.println("Validating Signature correct: " + isCorrect);
    }
}
