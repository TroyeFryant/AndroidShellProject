package com.shell.protector;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class DexEncryptor {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 16;
    private static final int IV_SIZE = 16;

    private static final byte[] DEFAULT_KEY = {
            0x53, 0x68, 0x65, 0x6C, 0x6C, 0x50, 0x72, 0x6F,
            0x74, 0x65, 0x63, 0x74, 0x30, 0x31, 0x32, 0x33
    };

    private final byte[] key;

    public DexEncryptor() {
        this(DEFAULT_KEY);
    }

    public static byte[] generateRandomKey() {
        byte[] k = new byte[KEY_SIZE];
        new SecureRandom().nextBytes(k);
        return k;
    }

    public DexEncryptor(byte[] key) {
        if (key == null || key.length != KEY_SIZE) {
            throw new IllegalArgumentException("AES-128 requires a 16-byte key");
        }
        this.key = key.clone();
    }

    private static final int HMAC_SIZE = 32;

    /**
     * 加密原始字节数据，返回格式: [IV(16)] + [ciphertext] + [HMAC-SHA256(32)]
     */
    public byte[] encrypt(byte[] plainData) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plainData);

        byte[] ivAndCipher = new byte[IV_SIZE + encrypted.length];
        System.arraycopy(iv, 0, ivAndCipher, 0, IV_SIZE);
        System.arraycopy(encrypted, 0, ivAndCipher, IV_SIZE, encrypted.length);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] hmac = mac.doFinal(ivAndCipher);

        byte[] result = new byte[ivAndCipher.length + HMAC_SIZE];
        System.arraycopy(ivAndCipher, 0, result, 0, ivAndCipher.length);
        System.arraycopy(hmac, 0, result, ivAndCipher.length, HMAC_SIZE);
        return result;
    }

    /**
     * 解密由 {@link #encrypt} 产出的数据（含 HMAC 校验）
     */
    public byte[] decrypt(byte[] cipherData) throws Exception {
        if (cipherData.length < IV_SIZE + HMAC_SIZE) {
            throw new IllegalArgumentException("Cipher data too short");
        }

        int payloadLen = cipherData.length - HMAC_SIZE;
        byte[] payload = new byte[payloadLen];
        System.arraycopy(cipherData, 0, payload, 0, payloadLen);
        byte[] expectedHmac = new byte[HMAC_SIZE];
        System.arraycopy(cipherData, payloadLen, expectedHmac, 0, HMAC_SIZE);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] actualHmac = mac.doFinal(payload);
        if (!java.security.MessageDigest.isEqual(expectedHmac, actualHmac)) {
            throw new SecurityException("HMAC verification failed: data tampered");
        }

        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(payload, 0, iv, 0, IV_SIZE);
        byte[] encrypted = new byte[payloadLen - IV_SIZE];
        System.arraycopy(payload, IV_SIZE, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, ALGORITHM), new IvParameterSpec(iv));
        return cipher.doFinal(encrypted);
    }

    /**
     * 读取 classes.dex 文件并返回加密后的字节流
     */
    public byte[] encryptDexFile(String dexPath) throws Exception {
        byte[] dexBytes = Files.readAllBytes(Paths.get(dexPath));
        System.out.printf("[DexEncryptor] 读取 DEX 文件: %s (%d bytes)%n", dexPath, dexBytes.length);
        byte[] result = encrypt(dexBytes);
        System.out.printf("[DexEncryptor] 加密完成，输出大小: %d bytes (含 16 bytes IV)%n", result.length);
        return result;
    }
}
