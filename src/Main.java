import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.*;

public class Main {
    public static void main(String[] args) {
        try {
            // Task 1: Split the content of ciphertext.enc
            byte[] ciphertext = Files.readAllBytes(Paths.get("C:\\Users\\talal\\Desktop\\Security Lab\\resources\\ciphertext.enc"));
            byte[] encryptedSymmetricKey = Arrays.copyOfRange(ciphertext, 0, 128);
            byte[] encryptedIV = Arrays.copyOfRange(ciphertext, 128, 256);
            byte[] encryptedHmacKey = Arrays.copyOfRange(ciphertext, 256, 384);
            byte[] encryptedData = Arrays.copyOfRange(ciphertext, 384, ciphertext.length);

            // Task 2: Decrypt using the private key from the keystore
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(new FileInputStream("C:\\Users\\talal\\Desktop\\Security Lab\\resources\\lab1Store"), "lab1StorePass".toCharArray());
            PrivateKey privateKey = (PrivateKey) keystore.getKey("lab1EncKeys", "lab1KeyPass".toCharArray());

            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] symmetricKey = rsaCipher.doFinal(encryptedSymmetricKey);
            byte[] iv = rsaCipher.doFinal(encryptedIV);

            // Task 3: Decrypt the data using the decrypted key and IV
            SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decryptedData = aesCipher.doFinal(encryptedData);

            // Task 4: Verify integrity using Message Authentication Code (HmacMD5)
            byte[] hmacKey = rsaCipher.doFinal(encryptedHmacKey);
            String givenHMAC = Files.readString(Paths.get("C:\\Users\\talal\\Desktop\\Security Lab\\resources\\ciphertext.mac2.txt"));
            SecretKeySpec hmacKeySpec = new SecretKeySpec(hmacKey, "HmacMD5");
            Mac hmac = Mac.getInstance("HmacMD5");
            hmac.init(hmacKeySpec);
            byte[] computedHmac = hmac.doFinal(decryptedData);
            String computedHMACtoHex = bytesToHex(computedHmac);
            boolean integrityVerified = computedHMACtoHex.equals(givenHMAC);

            // Additional code to use the decrypted data as needed
            String plaintext = new String(decryptedData, StandardCharsets.UTF_8);
            System.out.println("Decrypted Message: " + plaintext);
            System.out.println("Integrity Verified: " + integrityVerified);
            
            System.out.println("Given HMAC: " + givenHMAC);
            System.out.println("Computed HMAC: " + computedHMACtoHex);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String bytesToHex(byte[] bytes) {
    StringBuilder hexString = new StringBuilder(2 * bytes.length);

    for (byte b : bytes) {
        // Convert each byte to a two-digit hexadecimal representation
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) {
            hexString.append('0');  // Ensure that the string has two characters
        }
        hexString.append(hex);
    }

    return hexString.toString();
    
    }
}
