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

import dalvik.system.DexClassLoader;

public class ProxyApplication extends Application {

    private static final String ENCRYPTED_DEX_ASSET = "classes.dex.enc";
    private static final String CONFIG_ASSET        = "shell_config.properties";
    private static final String CONFIG_KEY_APP      = "original_application";

    private String originalAppClassName;

    static {
        System.loadLibrary("guard");
    }

    public native byte[] decryptDex(byte[] data);
    public native void initAntiDebug();

    // ── attachBaseContext ────────────────────────────────────────

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

        try {
            initAntiDebug();

            byte[] encryptedDex = readAsset(base, ENCRYPTED_DEX_ASSET);
            byte[] decryptedDex = decryptDex(encryptedDex);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                loadDexInMemory(base, decryptedDex);
            } else {
                loadDexFromDisk(base, decryptedDex);
            }

            originalAppClassName = readOriginalAppName(base);

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
    //  DEX 加载策略
    // ════════════════════════════════════════════════════════════

    /**
     * API 26+: InMemoryDexClassLoader 纯内存加载，天然兼容 Android 14+ 只读要求。
     */
    private void loadDexInMemory(Context base, byte[] dexBytes) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(dexBytes);
        ClassLoader parent = base.getClassLoader();

        ClassLoader memLoader = createInMemoryDexClassLoader(buffer, parent);

        RefInvoke.injectDexElements(memLoader, parent);
    }

    /**
     * API < 26: 写入 code_cache 后通过 DexClassLoader 加载。
     * Android 14+ (API 34) 要求动态加载的文件必须为只读，此处做了兼容处理。
     */
    private void loadDexFromDisk(Context base, byte[] dexBytes) throws Exception {
        File cacheDir = ensureDir(base.getApplicationInfo().dataDir, "code_cache");
        File optDir   = ensureDir(cacheDir.getAbsolutePath(), "opt_dex");

        File dexFile = new File(cacheDir, "classes.dex");
        try (FileOutputStream fos = new FileOutputStream(dexFile)) {
            fos.write(dexBytes);
        }

        // Android 14+ 安全策略：动态代码文件必须设置为只读
        dexFile.setReadOnly();

        ClassLoader parent = base.getClassLoader();
        DexClassLoader diskLoader = new DexClassLoader(
                dexFile.getAbsolutePath(),
                optDir.getAbsolutePath(),
                null,
                parent);

        RefInvoke.injectDexElements(diskLoader, parent);

        dexFile.delete();
    }

    private static ClassLoader createInMemoryDexClassLoader(ByteBuffer buffer,
                                                             ClassLoader parent) throws Exception {
        Class<?> clazz = Class.forName("dalvik.system.InMemoryDexClassLoader");
        Constructor<?> ctor = clazz.getConstructor(ByteBuffer.class, ClassLoader.class);
        return (ClassLoader) ctor.newInstance(buffer, parent);
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

    private static File ensureDir(String parent, String child) {
        File dir = new File(parent, child);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }
}
