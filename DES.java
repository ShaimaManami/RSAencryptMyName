package com.example.hash;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class DES {

    public static Cipher encryptionCipher;
    public static Cipher decryptionCipher;
    public static byte[] IV = {24, 23, 10, 44, 58, 19, 63, 97};
    public static byte[] plaintext;
    public static byte[] ciphertext;
    public static byte[] decrypted_plaintext;
    public static SecretKey secret;
    public static AlgorithmParameterSpec params;
    
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {
        plaintext = "Shaima Alsharif".getBytes(StandardCharsets.UTF_8);
//        Generate the secret key
        secret = KeyGenerator.getInstance("DES").generateKey();
//        Use an Initialization Vector for better security
        params = new IvParameterSpec(IV);
        System.out.println("Before encryption\n" + new String(plaintext));
        ciphertext = encrypt(secret, params, plaintext);
        System.out.println("After encryption\n" + new String(ciphertext));
        decrypted_plaintext = decrypt(secret, params, ciphertext);
        System.out.println("After decryption\n" + new String(decrypted_plaintext));
    }

    private static byte[] encrypt(SecretKey secret, AlgorithmParameterSpec params, byte[] plaintext) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
//        This method does the encryption and returns the ciphertext as a byte array
        encryptionCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, secret, params);
        return encryptionCipher.doFinal(plaintext);
    }

    private static byte[] decrypt(SecretKey secret, AlgorithmParameterSpec params, byte[] ciphertext) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
//        This method does the decryption and returns the plaintext as a byte array
        decryptionCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        decryptionCipher.init(Cipher.DECRYPT_MODE, secret, params);
        return decryptionCipher.doFinal(ciphertext);
    }

}
