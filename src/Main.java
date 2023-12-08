import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Main {
    public static void main(String[] args) {
        try {
            //Split the content of ciphertext.enc
            //to get the data needed for decryption
            byte[] ciphertext = Files.readAllBytes(Paths.get("C:\\Users\\talal\\Desktop\\Security Lab\\resources\\ciphertext.enc"));
            byte[] encryptedSymmetricKey = Arrays.copyOfRange(ciphertext, 0, 128);
            byte[] encryptedIV = Arrays.copyOfRange(ciphertext, 128, 256);
            byte[] encryptedHmacKey = Arrays.copyOfRange(ciphertext, 256, 384);
            byte[] encryptedData = Arrays.copyOfRange(ciphertext, 384, ciphertext.length);

            //Decrypt The symmetric key and IV using the private key from the keystore
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(new FileInputStream("C:\\Users\\talal\\Desktop\\Security Lab\\resources\\lab1Store"), "lab1StorePass".toCharArray());
            PrivateKey privateKey = (PrivateKey) keystore.getKey("lab1EncKeys", "lab1KeyPass".toCharArray());
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] symmetricKey = rsaCipher.doFinal(encryptedSymmetricKey);
            byte[] iv = rsaCipher.doFinal(encryptedIV);

            //Decrypt the data using the decrypted key and IV
            SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decryptedData = aesCipher.doFinal(encryptedData);

            //Verify integrity using Message Authentication Code (HmacMD5)
            byte[] hmacKey = rsaCipher.doFinal(encryptedHmacKey);
            String givenHMAC = Files.readString(Paths.get("C:\\Users\\talal\\Desktop\\Security Lab\\resources\\ciphertext.mac2.txt"));
            SecretKeySpec hmacKeySpec = new SecretKeySpec(hmacKey, "HmacMD5");
            Mac hmac = Mac.getInstance("HmacMD5");
            hmac.init(hmacKeySpec);
            byte[] computedHmac = hmac.doFinal(decryptedData);
            String computedHMACtoHex = bytesToHex(computedHmac);
            boolean integrityVerified = computedHMACtoHex.equals(givenHMAC);
            String plaintext = new String(decryptedData, StandardCharsets.UTF_8);

            //Verify the digital signature
            byte[] ciph1 = Files.readAllBytes(Paths.get("C:\\Users\\talal\\Desktop\\Security Lab\\resources\\ciphertext.enc.sig1"));
            byte[] ciph2 = Files.readAllBytes(Paths.get("C:\\Users\\talal\\Desktop\\Security Lab\\resources\\ciphertext.enc.sig2"));

            boolean isVerified1 = verification(plaintext, ciph1);
            boolean isVerified2 = verification(plaintext, ciph2);

            System.out.println("Decrypted Message: " + plaintext);
            System.out.println("Integrity Verified: " + integrityVerified);
            System.out.println("Digital Signature Verified(File 1): " + isVerified1);
            System.out.println("Digital Signature Verified(File 2): " + isVerified2);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //verify digital signature
    public static boolean verification(String plaintext, byte[] ciph) {
        try {
            FileInputStream readPublicKey = new FileInputStream("C:\\Users\\talal\\Desktop\\Security Lab\\resources\\lab1Sign.cert");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(readPublicKey);
            PublicKey publickey = x509Certificate.getPublicKey();
            Signature sig = Signature.getInstance("SHA1withRSA");
            boolean isVerified;
            sig.initVerify(publickey);
            sig.update(plaintext.getBytes());
            isVerified = sig.verify(ciph);
            return isVerified;
        } catch(Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    //Convert byte[] to hexadecimal represenation
    public static String bytesToHex(byte[] bytes) {
    StringBuilder hexString = new StringBuilder(2 * bytes.length);

    for (byte b : bytes) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) {
            hexString.append('0');
        }
        hexString.append(hex);
    }

    return hexString.toString();
    
    }
}
