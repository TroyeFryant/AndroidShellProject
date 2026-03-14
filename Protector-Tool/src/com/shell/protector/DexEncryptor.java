package com.shell.protector;

import javax.crypto.Cipher;
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

    public DexEncryptor(byte[] key) {
        if (key == null || key.length != KEY_SIZE) {
            throw new IllegalArgumentException("AES-128 requires a 16-byte key");
        }
        this.key = key.clone();
    }

    /**
     * 加密原始字节数据，返回格式: [IV(16 bytes)] + [encrypted data]
     */
    public byte[] encrypt(byte[] plainData) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(plainData);

        byte[] result = new byte[IV_SIZE + encrypted.length];
        System.arraycopy(iv, 0, result, 0, IV_SIZE);
        System.arraycopy(encrypted, 0, result, IV_SIZE, encrypted.length);
        return result;
    }

    /**
     * 解密由 {@link #encrypt} 产出的数据
     */
    public byte[] decrypt(byte[] cipherData) throws Exception {
        if (cipherData.length < IV_SIZE) {
            throw new IllegalArgumentException("Cipher data too short");
        }

        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(cipherData, 0, iv, 0, IV_SIZE);

        byte[] encrypted = new byte[cipherData.length - IV_SIZE];
        System.arraycopy(cipherData, IV_SIZE, encrypted, 0, encrypted.length);

        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
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
