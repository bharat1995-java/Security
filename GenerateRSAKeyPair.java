package javaExample;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
public class GenerateRSAKeyPair {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        // Save the keys to files
        Files.write(Paths.get("publicKey"), publicKey.getEncoded());
        Files.write(Paths.get("privateKey"), privateKey.getEncoded());

        System.out.println("Keys generated and saved to files.");

	}

}
