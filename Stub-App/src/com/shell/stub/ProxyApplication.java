package com.shell.stub;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.res.AssetManager;
import android.os.Build;

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

    private static final String T = "ShellProxy";

    private static final String ENCRYPTED_DEX_ASSET = "classes.dex.enc";
    private static final String CONFIG_ASSET        = "shell_config.properties";
    private static final String CONFIG_KEY_APP      = "original_application";

    private static boolean sNativeLoaded;

    private String originalAppClassName;

    static {
        try {
            System.loadLibrary("guard");
            sNativeLoaded = true;
        } catch (UnsatisfiedLinkError ignored) {
            sNativeLoaded = false;
        }
    }

    public native byte[] decryptDex(byte[] data);
    public native void initAntiDebug();

    // ── attachBaseContext ────────────────────────────────────────

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

        try {
            android.util.Log.e(T, ">>> attachBaseContext START, native=" + sNativeLoaded);

            if (sNativeLoaded) {
                initAntiDebug();
            }

            byte[] encryptedBlob = readAsset(base, ENCRYPTED_DEX_ASSET);
            android.util.Log.e(T, ">>> encrypted blob size=" + encryptedBlob.length);

            byte[] decryptedBlob = sNativeLoaded
                    ? decryptDex(encryptedBlob)
                    : decryptDexFallback(encryptedBlob);
            android.util.Log.e(T, ">>> decrypted blob size=" + decryptedBlob.length);

            java.util.List<byte[]> dexList = parseDexBlob(decryptedBlob);
            android.util.Log.e(T, ">>> dex count=" + dexList.size());

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                android.util.Log.e(T, ">>> loadMultiDexInMemory API=" + Build.VERSION.SDK_INT);
                loadMultiDexInMemory(base, dexList);
            } else {
                loadMultiDexFromDisk(base, dexList);
            }

            android.util.Log.e(T, ">>> DEX injection done");

            originalAppClassName = readOriginalAppName(base);
            android.util.Log.e(T, ">>> originalApp=" + originalAppClassName);

        } catch (Exception e) {
            android.util.Log.e(T, ">>> FAILED", e);
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

    private String readOriginalAppName(Context ctx) throws IOException {
        Properties props = new Properties();
        try (InputStream is = ctx.getAssets().open(CONFIG_ASSET)) {
            props.load(is);
        }
        return props.getProperty(CONFIG_KEY_APP, "");
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

    private static final byte[] AES_KEY = {
            0x53, 0x68, 0x65, 0x6C, 0x6C, 0x50, 0x72, 0x6F,
            0x74, 0x65, 0x63, 0x74, 0x30, 0x31, 0x32, 0x33
    };

    private static byte[] decryptDexFallback(byte[] cipherData) throws Exception {
        byte[] iv = new byte[16];
        System.arraycopy(cipherData, 0, iv, 0, 16);
        byte[] encrypted = new byte[cipherData.length - 16];
        System.arraycopy(cipherData, 16, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(AES_KEY, "AES"),
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
