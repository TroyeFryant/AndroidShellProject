package com.shell.stub;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.res.AssetManager;
import android.os.Build;
import android.provider.Settings;

import com.shell.stub.utils.RefInvoke;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import dalvik.system.DexClassLoader;

public class ProxyApplication extends Application {

    private static final String ENCRYPTED_DEX_ASSET = "classes.dex.enc";
    private static final String CONFIG_ASSET        = "shell_config.properties";
    private static final String CONFIG_KEY_APP      = "original_application";
    private static final String CONFIG_KEY_DEX_KEY  = "dex_key";

    private static boolean sNativeLoaded;
    private static String sBenchmarkResult;

    private String originalAppClassName;

    static {
        try {
            System.loadLibrary("guard");
            sNativeLoaded = true;
        } catch (UnsatisfiedLinkError ignored) {
            sNativeLoaded = false;
        }
    }

    public native byte[] decryptDex(byte[] data, byte[] key);
    public native void initAntiDebug();
    public native void timingCheck();

    // ── attachBaseContext ────────────────────────────────────────

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

        try {
            long t0 = System.nanoTime();

            checkJavaDebug(base);

            if (sNativeLoaded) {
                initAntiDebug();
            }
            long t1 = System.nanoTime();

            Properties config = loadConfig(base);
            byte[] dexKey = android.util.Base64.decode(
                    config.getProperty(CONFIG_KEY_DEX_KEY, ""), android.util.Base64.DEFAULT);

            byte[] encryptedBlob = readAsset(base, ENCRYPTED_DEX_ASSET);
            long t2 = System.nanoTime();

            byte[] decryptedBlob = sNativeLoaded
                    ? decryptDex(encryptedBlob, dexKey)
                    : decryptDexFallback(encryptedBlob, dexKey);
            long t3 = System.nanoTime();

            if (sNativeLoaded) timingCheck();

            java.util.List<byte[]> dexList = parseDexBlob(decryptedBlob);
            verifyDexHeaders(dexList);
            long t4 = System.nanoTime();

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                loadMultiDexInMemory(base, dexList);
            } else {
                loadMultiDexFromDisk(base, dexList);
            }
            long t5 = System.nanoTime();

            clearDecryptedData(decryptedBlob, dexList);

            originalAppClassName = config.getProperty(CONFIG_KEY_APP, "");
            long t6 = System.nanoTime();

            sBenchmarkResult = String.format(
                    "AntiDebug=%dms, Read=%dms, Decrypt=%dms, Verify=%dms, Load=%dms, Total=%dms",
                    (t1-t0)/1000000, (t2-t1)/1000000, (t3-t2)/1000000,
                    (t4-t3)/1000000, (t5-t4)/1000000, (t6-t0)/1000000);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ── onCreate ────────────────────────────────────────────────

    @Override
    public void onCreate() {
        super.onCreate();

        if (originalAppClassName == null || originalAppClassName.isEmpty()) {
            return;
        }

        try {
            replaceApplication();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ════════════════════════════════════════════════════════════
    //  设备绑定密钥派生 (HMAC-SHA256)
    // ════════════════════════════════════════════════════════════

    @SuppressWarnings("deprecation")
    private static byte[] deriveDeviceKey(Context ctx, byte[] rawKey) throws Exception {
        String androidId = Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
        if (androidId == null) androidId = "unknown";

        byte[] sigHash;
        try {
            PackageInfo pi = ctx.getPackageManager().getPackageInfo(
                    ctx.getPackageName(), PackageManager.GET_SIGNATURES);
            Signature sig = pi.signatures[0];
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            sigHash = md.digest(sig.toByteArray());
        } catch (Exception e) {
            sigHash = new byte[32];
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(rawKey);
        bos.write(androidId.getBytes("UTF-8"));
        bos.write(sigHash);

        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(rawKey, "HmacSHA256"));
        byte[] derived = mac.doFinal(bos.toByteArray());

        byte[] key16 = new byte[16];
        System.arraycopy(derived, 0, key16, 0, 16);
        return key16;
    }

    // ════════════════════════════════════════════════════════════
    //  Java 层调试检测
    // ════════════════════════════════════════════════════════════

    private static void checkJavaDebug(Context ctx) {
        if (android.os.Debug.isDebuggerConnected() || android.os.Debug.waitingForDebugger()) {
            throw new RuntimeException();
        }
        ApplicationInfo ai = ctx.getApplicationInfo();
        if ((ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            throw new RuntimeException();
        }
    }

    // ════════════════════════════════════════════════════════════
    //  DEX 头部校验
    // ════════════════════════════════════════════════════════════

    private static void verifyDexHeaders(java.util.List<byte[]> dexList) {
        for (byte[] dex : dexList) {
            if (dex.length < 12) throw new RuntimeException("Invalid DEX size");
            if (dex[0] != 0x64 || dex[1] != 0x65 || dex[2] != 0x78 || dex[3] != 0x0A) {
                throw new RuntimeException("Invalid DEX magic");
            }
            long stored = (dex[8] & 0xFFL) | ((dex[9] & 0xFFL) << 8) |
                          ((dex[10] & 0xFFL) << 16) | ((dex[11] & 0xFFL) << 24);
            long computed = adler32(dex, 12, dex.length - 12);
            if (stored != computed) {
                throw new RuntimeException("DEX checksum mismatch");
            }
        }
    }

    private static long adler32(byte[] data, int off, int len) {
        long a = 1, b = 0;
        for (int i = off; i < off + len; i++) {
            a = (a + (data[i] & 0xFF)) % 65521;
            b = (b + a) % 65521;
        }
        return (b << 16) | a;
    }

    // ════════════════════════════════════════════════════════════
    //  解密后内存清理
    // ════════════════════════════════════════════════════════════

    private static void clearDecryptedData(byte[] blob, java.util.List<byte[]> dexList) {
        if (blob != null) java.util.Arrays.fill(blob, (byte) 0);
        for (byte[] dex : dexList) {
            if (dex != null) java.util.Arrays.fill(dex, (byte) 0);
        }
    }

    // ════════════════════════════════════════════════════════════
    //  DEX 加载策略（多 DEX 支持）
    // ════════════════════════════════════════════════════════════

    private void loadMultiDexInMemory(Context base, java.util.List<byte[]> dexList) throws Exception {
        ByteBuffer[] buffers = new ByteBuffer[dexList.size()];
        for (int i = 0; i < dexList.size(); i++) {
            buffers[i] = ByteBuffer.wrap(dexList.get(i));
        }

        ClassLoader parent = base.getClassLoader();
        Class<?> clazz = Class.forName("dalvik.system.InMemoryDexClassLoader");
        Constructor<?> ctor = clazz.getConstructor(ByteBuffer[].class, ClassLoader.class);
        ClassLoader memLoader = (ClassLoader) ctor.newInstance(buffers, parent);

        RefInvoke.injectDexElements(memLoader, parent);
    }

    private void loadMultiDexFromDisk(Context base, java.util.List<byte[]> dexList) throws Exception {
        File cacheDir = ensureDir(base.getApplicationInfo().dataDir, "code_cache");
        File optDir   = ensureDir(cacheDir.getAbsolutePath(), "opt_dex");
        ClassLoader parent = base.getClassLoader();

        StringBuilder dexPaths = new StringBuilder();
        java.util.List<File> tempFiles = new ArrayList<>();

        for (int i = 0; i < dexList.size(); i++) {
            String name = (i == 0) ? "classes.dex" : ("classes" + (i + 1) + ".dex");
            File f = new File(cacheDir, name);
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(dexList.get(i));
            }
            f.setReadOnly();
            tempFiles.add(f);
            if (dexPaths.length() > 0) dexPaths.append(File.pathSeparator);
            dexPaths.append(f.getAbsolutePath());
        }

        DexClassLoader diskLoader = new DexClassLoader(
                dexPaths.toString(), optDir.getAbsolutePath(), null, parent);
        RefInvoke.injectDexElements(diskLoader, parent);

        for (File f : tempFiles) f.delete();
    }

    // ════════════════════════════════════════════════════════════
    //  Application 替换
    // ════════════════════════════════════════════════════════════

    private void replaceApplication() throws Exception {
        Class<?> realAppClass = getClassLoader().loadClass(originalAppClassName);
        Application realApp = (Application) realAppClass.newInstance();

        Object activityThread = RefInvoke.getActivityThread();
        Object loadedApk = RefInvoke.getLoadedApk(activityThread);

        RefInvoke.setLoadedApkApplication(loadedApk, realApp);
        RefInvoke.setInitialApplication(activityThread, realApp);

        ArrayList<Object> allApps = RefInvoke.getAllApplications(activityThread);
        allApps.remove(this);
        allApps.add(realApp);

        ApplicationInfo appInfo = (ApplicationInfo) RefInvoke.getFieldValue(
                "android.app.LoadedApk", loadedApk, "mApplicationInfo");
        appInfo.className = originalAppClassName;

        Method attachMethod = Application.class.getDeclaredMethod("attach", Context.class);
        attachMethod.setAccessible(true);
        attachMethod.invoke(realApp, getBaseContext());

        RefInvoke.setFieldValue(
                "android.app.ContextImpl", getBaseContext(), "mOuterContext", realApp);

        realApp.onCreate();
    }

    // ════════════════════════════════════════════════════════════
    //  辅助方法
    // ════════════════════════════════════════════════════════════

    private static byte[] readAsset(Context ctx, String name) throws IOException {
        AssetManager am = ctx.getAssets();
        try (InputStream is = am.open(name);
             ByteArrayOutputStream bos = new ByteArrayOutputStream(is.available())) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) {
                bos.write(buf, 0, n);
            }
            return bos.toByteArray();
        }
    }

    private static Properties loadConfig(Context ctx) throws IOException {
        Properties props = new Properties();
        try (InputStream is = ctx.getAssets().open(CONFIG_ASSET)) {
            props.load(is);
        }
        return props;
    }

    private static java.util.List<byte[]> parseDexBlob(byte[] blob) {
        java.util.List<byte[]> result = new ArrayList<>();
        int offset = 0;
        int count = readInt(blob, offset); offset += 4;
        for (int i = 0; i < count; i++) {
            int size = readInt(blob, offset); offset += 4;
            byte[] dex = new byte[size];
            System.arraycopy(blob, offset, dex, 0, size);
            offset += size;
            result.add(dex);
        }
        return result;
    }

    private static int readInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
             | ((data[offset + 1] & 0xFF) << 16)
             | ((data[offset + 2] & 0xFF) << 8)
             | (data[offset + 3] & 0xFF);
    }

    private static final int HMAC_LEN = 32;

    private static byte[] decryptDexFallback(byte[] cipherData, byte[] key) throws Exception {
        int payloadLen = cipherData.length - HMAC_LEN;
        byte[] payload = new byte[payloadLen];
        System.arraycopy(cipherData, 0, payload, 0, payloadLen);
        byte[] expectedHmac = new byte[HMAC_LEN];
        System.arraycopy(cipherData, payloadLen, expectedHmac, 0, HMAC_LEN);

        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] actualHmac = mac.doFinal(payload);
        if (!java.security.MessageDigest.isEqual(expectedHmac, actualHmac)) {
            throw new SecurityException("HMAC verification failed");
        }

        byte[] iv = new byte[16];
        System.arraycopy(payload, 0, iv, 0, 16);
        byte[] encrypted = new byte[payloadLen - 16];
        System.arraycopy(payload, 16, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new IvParameterSpec(iv));
        return cipher.doFinal(encrypted);
    }

    private static File ensureDir(String parent, String child) {
        File dir = new File(parent, child);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }
}
