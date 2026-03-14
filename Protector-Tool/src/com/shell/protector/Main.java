package com.shell.protector;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 加壳工具主入口。
 * <p>
 * 用法: java com.shell.protector.Main &lt;input_apk&gt; &lt;output_dir&gt;
 * <p>
 * 流程:
 * <ol>
 *   <li>从 APK 中提取 classes.dex 和 AndroidManifest.xml</li>
 *   <li>使用 AES-128-CBC 加密 classes.dex</li>
 *   <li>修改 AndroidManifest.xml，将 application 类名替换为壳入口</li>
 *   <li>将加密后的 DEX、修改后的清单和配置文件写入输出目录</li>
 * </ol>
 */
public class Main {

    private static final String ENCRYPTED_DEX_NAME  = "classes.dex.enc";
    private static final String MODIFIED_MANIFEST    = "AndroidManifest.xml";
    private static final String CONFIG_FILE_NAME     = "shell_config.properties";

    private static final String CONFIG_KEY_ORIGINAL_APP = "original_application";

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Android 加壳工具 v1.0");
            System.out.println("用法: java com.shell.protector.Main <input_apk> <output_dir>");
            System.out.println();
            System.out.println("  input_apk   — 原始 APK 文件路径");
            System.out.println("  output_dir  — 输出目录（自动创建）");
            System.exit(1);
        }

        String apkPath   = args[0];
        String outputDir = args[1];

        try {
            run(apkPath, outputDir);
        } catch (Exception e) {
            System.err.println("[ERROR] 加壳失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(2);
        }
    }

    private static void run(String apkPath, String outputDir) throws Exception {
        Path apkFile = Paths.get(apkPath);
        if (!Files.isRegularFile(apkFile)) {
            throw new FileNotFoundException("APK 文件不存在: " + apkPath);
        }

        Path outDir = Paths.get(outputDir);
        Files.createDirectories(outDir);

        System.out.println("========================================");
        System.out.println("       Android 加壳工具 v1.0");
        System.out.println("========================================");
        System.out.printf("输入 APK : %s%n", apkFile.toAbsolutePath());
        System.out.printf("输出目录 : %s%n", outDir.toAbsolutePath());
        System.out.println("----------------------------------------");

        // ① 从 APK 提取 classes.dex 和 AndroidManifest.xml
        byte[] dexBytes;
        byte[] manifestBytes;

        try (ZipFile zip = new ZipFile(apkFile.toFile())) {
            dexBytes = extractEntry(zip, "classes.dex");
            manifestBytes = extractEntry(zip, "AndroidManifest.xml");
        }

        System.out.printf("[提取] classes.dex          : %d bytes%n", dexBytes.length);
        System.out.printf("[提取] AndroidManifest.xml  : %d bytes%n", manifestBytes.length);

        // ② 加密 DEX
        System.out.println("----------------------------------------");
        DexEncryptor encryptor = new DexEncryptor();
        byte[] encryptedDex = encryptor.encrypt(dexBytes);
        System.out.printf("[加密] AES-128-CBC 加密完成 : %d bytes -> %d bytes%n",
                dexBytes.length, encryptedDex.length);

        // ③ 修改清单
        System.out.println("----------------------------------------");
        ManifestEditor editor = new ManifestEditor();
        ManifestEditor.EditResult editResult = editor.process(manifestBytes);
        String originalApp = editResult.getOriginalApplicationName();
        byte[] modifiedManifest = editResult.getModifiedManifest();

        // ④ 写出结果
        System.out.println("----------------------------------------");

        Path encDexPath = outDir.resolve(ENCRYPTED_DEX_NAME);
        Files.write(encDexPath, encryptedDex);
        System.out.printf("[输出] %s  : %d bytes%n", ENCRYPTED_DEX_NAME, encryptedDex.length);

        Path manifestPath = outDir.resolve(MODIFIED_MANIFEST);
        Files.write(manifestPath, modifiedManifest);
        System.out.printf("[输出] %s : %d bytes%n", MODIFIED_MANIFEST, modifiedManifest.length);

        Path configPath = outDir.resolve(CONFIG_FILE_NAME);
        writeConfig(configPath, originalApp);
        System.out.printf("[输出] %s  : 原始 Application = %s%n",
                CONFIG_FILE_NAME, originalApp.isEmpty() ? "(默认)" : originalApp);

        System.out.println("========================================");
        System.out.println("加壳处理完成！");
        System.out.println("========================================");
    }

    private static byte[] extractEntry(ZipFile zip, String entryName) throws IOException {
        ZipEntry entry = zip.getEntry(entryName);
        if (entry == null) {
            throw new IOException("APK 中未找到 " + entryName);
        }
        try (InputStream is = zip.getInputStream(entry);
             ByteArrayOutputStream bos = new ByteArrayOutputStream((int) entry.getSize())) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) {
                bos.write(buf, 0, n);
            }
            return bos.toByteArray();
        }
    }

    private static void writeConfig(Path path, String originalApp) throws IOException {
        Properties props = new Properties();
        props.setProperty(CONFIG_KEY_ORIGINAL_APP, originalApp);
        try (OutputStream os = Files.newOutputStream(path)) {
            props.store(os, "Shell Protector Configuration — 壳程序配置");
        }
    }
}
