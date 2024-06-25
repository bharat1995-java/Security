package javaExample;

import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.Formatter;

public class GenerateSHA256Hash {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub

		if (args.length != 1) {
            System.out.println("Usage: java SHA256HashGenerator <file_path>");
            return;
        }

        String filePath = args[0];
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        try (FileInputStream fis = new FileInputStream(filePath)) {
            byte[] byteArray = new byte[1024];
            int bytesCount = 0;

            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }
        }

        byte[] hashBytes = digest.digest();
        System.out.println("SHA-256 hash: " + bytesToHex(hashBytes));
    }

    private static String bytesToHex(byte[] bytes) {
        try (Formatter formatter = new Formatter()) {
            for (byte b : bytes) {
                formatter.format("%02x", b);
            }
            return formatter.toString();
        }
    }

}
