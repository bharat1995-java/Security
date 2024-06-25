package javaExample;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;

public class RSAFileEncryptDecrypt {

    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java RSAFileEncryptDecrypt <mode> <keyfile> <inputfile>");
            System.out.println("Modes: encrypt, decrypt");
            return;
        }

        String mode = args[0];
        String keyFile = args[1];
        String inputFile = args[2];

        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(keyFile));
            Cipher rsaCipher = Cipher.getInstance("RSA");

            if (mode.equals("encrypt")) {
                PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
                rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

                // Generate AES key
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                SecretKey aesKey = keyGen.generateKey();

                // Encrypt AES key with RSA
                byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

                // Encrypt data with AES key
                Cipher aesCipher = Cipher.getInstance("AES");
                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                try (FileOutputStream fos = new FileOutputStream("encryptedFile.enc");
                     CipherOutputStream cos = new CipherOutputStream(fos, aesCipher)) {
                    fos.write(encryptedAesKey.length);
                    fos.write(encryptedAesKey);
                    Files.copy(Paths.get(inputFile), cos);
                }

                System.out.println("File encrypted and saved as encryptedFile.enc");

            } else if (mode.equals("decrypt")) {
                PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
                rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);

                try (FileInputStream fis = new FileInputStream(inputFile)) {
                    int aesKeyLength = fis.read();
                    byte[] encryptedAesKey = new byte[aesKeyLength];
                    fis.read(encryptedAesKey);

                    // Decrypt AES key with RSA
                    byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
                    SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

                    // Decrypt data with AES key
                    Cipher aesCipher = Cipher.getInstance("AES");
                    aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
                    try (CipherInputStream cis = new CipherInputStream(fis, aesCipher);
                         FileOutputStream fos = new FileOutputStream("decryptedFile.txt")) {
                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        while ((bytesRead = cis.read(buffer)) != -1) {
                            fos.write(buffer, 0, bytesRead);
                        }
                    }

                    System.out.println("File decrypted and saved as decryptedFile.txt");
                }

            } else {
                System.out.println("Invalid mode. Use 'encrypt' or 'decrypt'.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
