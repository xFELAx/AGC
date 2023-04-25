import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public class BlockCipherExample {

    public static void main(String[] args) throws Exception {

        String inputFile1 = "file1.txt";
        String inputFile2 = "file2.txt";
        String inputFile3 = "file3.txt";

        String keyString = "mySecretKey12345"; // klucz szyfrujący
        byte[] keyData = keyString.getBytes(StandardCharsets.UTF_8);

        SecretKeySpec key = new SecretKeySpec(keyData, "AES"); // klucz AES

        int[] fileSizes = {1048576, 5242880, 10485760}; // rozmiary plików

        for (int fileSize : fileSizes) {
            byte[] data1 = generateRandomData(fileSize); // generuje losowe dane o podanym rozmiarze
            byte[] data2 = generateRandomData(fileSize);
            byte[] data3 = generateRandomData(fileSize);

            Path inputPath1 = Paths.get(inputFile1);
            Path inputPath2 = Paths.get(inputFile2);
            Path inputPath3 = Paths.get(inputFile3);

            Files.write(inputPath1, data1); // zapisuje dane do pliku
            Files.write(inputPath2, data2);
            Files.write(inputPath3, data3);

            // szyfrowanie i deszyfrowanie w trybie ECB
            encryptAndDecrypt(key, inputPath1, "AES/ECB/PKCS5Padding");
            encryptAndDecrypt(key, inputPath2, "AES/ECB/PKCS5Padding");
            encryptAndDecrypt(key, inputPath3, "AES/ECB/PKCS5Padding");

            // szyfrowanie i deszyfrowanie w trybie CBC
            byte[] iv = generateRandomData(16); // inicjalizacja wektora (IV) dla CBC
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            encryptAndDecrypt(key, ivSpec, inputPath1, "AES/CBC/PKCS5Padding");
            encryptAndDecrypt(key, ivSpec, inputPath2, "AES/CBC/PKCS5Padding");
            encryptAndDecrypt(key, ivSpec, inputPath3, "AES/CBC/PKCS5Padding");

            // szyfrowanie i deszyfrowanie w trybie OFB
            byte[] iv2 = generateRandomData(16); // inicjalizacja wektora (IV) dla OFB
            IvParameterSpec ivSpec2 = new IvParameterSpec(iv2);
            encryptAndDecrypt(key, ivSpec2, inputPath1, "AES/OFB/PKCS5Padding");
            encryptAndDecrypt(key, ivSpec2, inputPath2, "AES/OFB/PKCS5Padding");
            encryptAndDecrypt(key, ivSpec2, inputPath3, "AES/OFB/PKCS5Padding");

            // szyfrowanie i deszyfrowanie w trybie CFB
            byte[] iv3 = generateRandomData(16); // inicjalizacja wektora (IV) dla CFB
            IvParameterSpec ivSpec3 = new IvParameterSpec(iv3);
            encryptAndDecrypt(key, ivSpec3, inputPath1, "AES/CFB/PKCS5Padding");
            encryptAndDecrypt(key, ivSpec3, inputPath2, "AES/CFB/PKCS5Padding");
            encryptAndDecrypt(key, ivSpec3, inputPath3, "AES/CFB/PKCS5Padding");

            // szyfrowanie i deszyfrowanie w trybie CTR
            byte[] nonce = generateRandomData(8, 16); // inicjalizacja wartości nonce dla CTR
            IvParameterSpec ivSpec4 = new IvParameterSpec(nonce);
            encryptAndDecrypt(key, ivSpec4, inputPath1, "AES/CTR/NoPadding");
            encryptAndDecrypt(key, ivSpec4, inputPath2, "AES/CTR/NoPadding");
            encryptAndDecrypt(key, ivSpec4, inputPath3, "AES/CTR/NoPadding");
        }
    }

    private static byte[] generateRandomData(int size) {
        byte[] data = new byte[size];
        new java.util.Random().nextBytes(data);
        return data;
    }

    private static byte[] generateRandomData(int size, int ivSize) {
        if (ivSize == 16) {
            byte[] data = new byte[16];
            new java.util.Random().nextBytes(data);
            return data;
        }
        byte[] data = new byte[size];
        new java.util.Random().nextBytes(data);
        return data;
    }

    private static void encryptAndDecrypt(SecretKeySpec key, IvParameterSpec ivSpec, Path inputPath, String cipherAlgorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        long startTime = System.nanoTime();
        byte[] encryptedData = cipher.doFinal(Files.readAllBytes(inputPath)); // szyfrowanie danych
        long endTime = System.nanoTime();
        long encryptionTime = endTime - startTime;
        System.out.println("Encryption time for " + inputPath.getFileName() + " using " + cipherAlgorithm + ": " + encryptionTime + " ns");

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        startTime = System.nanoTime();
        byte[] decryptedData = cipher.doFinal(encryptedData); // deszyfrowanie danych
        endTime = System.nanoTime();
        long decryptionTime = endTime - startTime;
        System.out.println("Decryption time for " + inputPath.getFileName() + " using " + cipherAlgorithm + ": " + decryptionTime + " ns");

        if (!Arrays.equals(decryptedData, Files.readAllBytes(inputPath))) {
            throw new RuntimeException("Decryption failed");
        }
    }

    private static void encryptAndDecrypt(SecretKeySpec key, Path inputPath, String cipherAlgorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        long startTime = System.nanoTime();
        byte[] encryptedData = cipher.doFinal(Files.readAllBytes(inputPath)); // szyfrowanie danych
        long endTime = System.nanoTime();
        long encryptionTime = endTime - startTime;
        System.out.println("Encryption time for " + inputPath.getFileName() + " using " + cipherAlgorithm + ": " + encryptionTime + " ns");

        cipher.init(Cipher.DECRYPT_MODE, key);
        startTime = System.nanoTime();
        byte[] decryptedData = cipher.doFinal(encryptedData); // deszyfrowanie danych
        endTime = System.nanoTime();
        long decryptionTime = endTime - startTime;
        System.out.println("Decryption time for " + inputPath.getFileName() + " using " + cipherAlgorithm + ": " + decryptionTime + " ns");

        if (!Arrays.equals(decryptedData, Files.readAllBytes(inputPath))) {
            throw new RuntimeException("Decryption failed");
        }
    }
}