package com.shell.stub.utils;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;

/**
 * 反射工具类 —— 封装对 Android 框架私有 API 的访问。
 * <p>
 * 通用能力：获取/设置私有字段、调用私有方法。
 * 专用能力：操作 ActivityThread、LoadedApk (mPackageInfo)、BaseDexClassLoader (DexPathList)。
 */
public final class RefInvoke {

    private RefInvoke() {}

    // ════════════════════════════════════════════════════════════
    //  一、通用反射：字段
    // ════════════════════════════════════════════════════════════

    /**
     * 获取实例字段值（按类名精确定位声明类）。
     */
    public static Object getFieldValue(String className, Object instance, String fieldName)
            throws Exception {
        Field field = Class.forName(className).getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(instance);
    }

    /**
     * 设置实例字段值（按类名精确定位声明类）。
     */
    public static void setFieldValue(String className, Object instance,
                                     String fieldName, Object value) throws Exception {
        Field field = Class.forName(className).getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(instance, value);
    }

    /**
     * 沿继承链向上查找字段并获取值 —— 适用于不确定字段声明在哪一层的场景。
     */
    public static Object getFieldValueHierarchy(Object instance, String fieldName)
            throws Exception {
        Field field = findFieldInHierarchy(instance.getClass(), fieldName);
        return field.get(instance);
    }

    /**
     * 沿继承链向上查找字段并设置值。
     */
    public static void setFieldValueHierarchy(Object instance, String fieldName, Object value)
            throws Exception {
        Field field = findFieldInHierarchy(instance.getClass(), fieldName);
        field.set(instance, value);
    }

    /**
     * 获取静态字段值。
     */
    public static Object getStaticFieldValue(String className, String fieldName) throws Exception {
        return getFieldValue(className, null, fieldName);
    }

    /**
     * 设置静态字段值。
     */
    public static void setStaticFieldValue(String className, String fieldName, Object value)
            throws Exception {
        setFieldValue(className, null, fieldName, value);
    }

    // ════════════════════════════════════════════════════════════
    //  二、通用反射：方法
    // ════════════════════════════════════════════════════════════

    /**
     * 调用实例方法。
     */
    public static Object invokeMethod(String className, Object instance,
                                      String methodName, Class<?>[] paramTypes,
                                      Object[] args) throws Exception {
        Method method = Class.forName(className).getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        return method.invoke(instance, args);
    }

    /**
     * 调用静态方法。
     */
    public static Object invokeStaticMethod(String className, String methodName,
                                            Class<?>[] paramTypes, Object[] args)
            throws Exception {
        return invokeMethod(className, null, methodName, paramTypes, args);
    }

    // ════════════════════════════════════════════════════════════
    //  三、ActivityThread / LoadedApk (mPackageInfo)
    // ════════════════════════════════════════════════════════════

    private static final String CLS_ACTIVITY_THREAD = "android.app.ActivityThread";
    private static final String CLS_APP_BIND_DATA   = "android.app.ActivityThread$AppBindData";
    private static final String CLS_LOADED_APK      = "android.app.LoadedApk";

    /**
     * 获取当前进程的 ActivityThread 单例。
     */
    public static Object getActivityThread() throws Exception {
        return invokeStaticMethod(CLS_ACTIVITY_THREAD, "currentActivityThread",
                new Class[]{}, new Object[]{});
    }

    /**
     * ActivityThread → mBoundApplication → info (LoadedApk)。
     */
    public static Object getLoadedApk(Object activityThread) throws Exception {
        Object boundApp = getFieldValue(CLS_ACTIVITY_THREAD, activityThread, "mBoundApplication");
        return getFieldValue(CLS_APP_BIND_DATA, boundApp, "info");
    }

    /**
     * 获取 ActivityThread.mInitialApplication。
     */
    public static Object getInitialApplication(Object activityThread) throws Exception {
        return getFieldValue(CLS_ACTIVITY_THREAD, activityThread, "mInitialApplication");
    }

    /**
     * 替换 ActivityThread.mInitialApplication。
     */
    public static void setInitialApplication(Object activityThread, Object app) throws Exception {
        setFieldValue(CLS_ACTIVITY_THREAD, activityThread, "mInitialApplication", app);
    }

    /**
     * 获取 ActivityThread.mAllApplications 列表。
     */
    @SuppressWarnings("unchecked")
    public static ArrayList<Object> getAllApplications(Object activityThread) throws Exception {
        return (ArrayList<Object>) getFieldValue(CLS_ACTIVITY_THREAD, activityThread,
                "mAllApplications");
    }

    /**
     * 获取 LoadedApk.mApplication。
     */
    public static Object getLoadedApkApplication(Object loadedApk) throws Exception {
        return getFieldValue(CLS_LOADED_APK, loadedApk, "mApplication");
    }

    /**
     * 替换 LoadedApk.mApplication。
     */
    public static void setLoadedApkApplication(Object loadedApk, Object app) throws Exception {
        setFieldValue(CLS_LOADED_APK, loadedApk, "mApplication", app);
    }

    // ════════════════════════════════════════════════════════════
    //  四、BaseDexClassLoader / DexPathList / dexElements
    // ════════════════════════════════════════════════════════════

    private static final String CLS_BASE_DEX_CL  = "dalvik.system.BaseDexClassLoader";
    private static final String CLS_DEX_PATH_LIST = "dalvik.system.DexPathList";

    /**
     * BaseDexClassLoader → pathList (DexPathList)。
     */
    public static Object getPathList(ClassLoader classLoader) throws Exception {
        return getFieldValue(CLS_BASE_DEX_CL, classLoader, "pathList");
    }

    /**
     * DexPathList → dexElements (Element[])。
     */
    public static Object[] getDexElements(Object pathList) throws Exception {
        return (Object[]) getFieldValue(CLS_DEX_PATH_LIST, pathList, "dexElements");
    }

    /**
     * 替换 DexPathList.dexElements。
     */
    public static void setDexElements(Object pathList, Object[] elements) throws Exception {
        setFieldValue(CLS_DEX_PATH_LIST, pathList, "dexElements", elements);
    }

    /**
     * 将 head[] 拼在 tail[] 前面并返回新数组 —— 用于把解密 Dex 注入到 ClassLoader 头部。
     */
    public static Object[] combineDexElements(Object[] head, Object[] tail) {
        Object[] combined = (Object[]) Array.newInstance(
                head.getClass().getComponentType(),
                head.length + tail.length);
        System.arraycopy(head, 0, combined, 0, head.length);
        System.arraycopy(tail, 0, combined, head.length, tail.length);
        return combined;
    }

    /**
     * 一步到位：从 sourceClassLoader 中提取 dexElements，注入到 targetClassLoader 的头部。
     */
    public static void injectDexElements(ClassLoader source, ClassLoader target) throws Exception {
        Object srcPathList = getPathList(source);
        Object[] srcElements = getDexElements(srcPathList);

        Object tgtPathList = getPathList(target);
        Object[] tgtElements = getDexElements(tgtPathList);

        Object[] merged = combineDexElements(srcElements, tgtElements);
        setDexElements(tgtPathList, merged);
    }

    // ════════════════════════════════════════════════════════════
    //  内部工具
    // ════════════════════════════════════════════════════════════

    private static Field findFieldInHierarchy(Class<?> clazz, String fieldName)
            throws NoSuchFieldException {
        Class<?> current = clazz;
        while (current != null) {
            try {
                Field f = current.getDeclaredField(fieldName);
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException(
                fieldName + " not found in hierarchy of " + clazz.getName());
    }
}
