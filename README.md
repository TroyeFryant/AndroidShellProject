# Android Shell Project — Android DEX 加壳框架

一套完整的 Android APK 加壳保护方案，包含 **PC 端加壳工具** 和 **设备端壳程序（Stub）** 两部分。

## 项目结构

```
AndroidShellProject/
├── Protector-Tool/                          # PC 端加壳工具 (Java 17)
│   ├── build.sh
│   └── src/com/shell/protector/
│       ├── DexEncryptor.java                # AES-128-CBC DEX 加密
│       ├── ManifestEditor.java              # AXML 二进制清单编辑
│       └── Main.java                        # 集成主入口
│
└── Stub-App/                                # 设备端壳程序
    ├── src/com/shell/stub/
    │   ├── ProxyApplication.java            # 壳入口 Application
    │   └── utils/
    │       └── RefInvoke.java               # 反射工具类
    └── app/src/main/cpp/
        ├── CMakeLists.txt                   # NDK 构建脚本 → libguard.so
        ├── anti_debug.h
        ├── anti_debug.cpp                   # 反调试 / 反 Frida / 模拟器检测
        └── guard.cpp                        # AES 解密 + JNI 注册
```

## 工作原理

```
 ┌──────────────────────────────────────────────────────────┐
 │                    PC 端: Protector-Tool                  │
 │                                                          │
 │  原始 APK ──┬── classes.dex ──→ AES-128-CBC 加密         │
 │             │                    ↓                       │
 │             │              classes.dex.enc               │
 │             │                                            │
 │             └── AndroidManifest.xml                      │
 │                    ↓                                     │
 │             替换 android:name →                          │
 │             com.shell.stub.ProxyApplication              │
 │                    ↓                                     │
 │             记录原始 Application 类名 →                   │
 │             shell_config.properties                      │
 └──────────────────────────────────────────────────────────┘

                        ↓ 重打包 APK

 ┌──────────────────────────────────────────────────────────┐
 │              设备端: Stub-App (壳程序运行时)               │
 │                                                          │
 │  1. System.loadLibrary("guard")                          │
 │     └─→ JNI_OnLoad: 注册 native 方法 + 启动反调试        │
 │                                                          │
 │  2. attachBaseContext:                                    │
 │     ├─ initAntiDebug()  → ptrace / TracerPid / Frida     │
 │     ├─ 读取 assets/classes.dex.enc                       │
 │     ├─ native decryptDex() → AES-128-CBC 解密            │
 │     ├─ API≥26: InMemoryDexClassLoader (纯内存)           │
 │     │  API<26: DexClassLoader (code_cache, 只读)         │
 │     └─ 注入 dexElements 到当前 ClassLoader               │
 │                                                          │
 │  3. onCreate:                                            │
 │     ├─ 读取 shell_config.properties                      │
 │     ├─ 反射实例化原始 Application                         │
 │     ├─ 替换 ActivityThread / LoadedApk 中所有引用         │
 │     └─ 调用原始 Application.onCreate()                   │
 └──────────────────────────────────────────────────────────┘
```

## 模块详解

### Protector-Tool（PC 端）

| 文件 | 功能 |
|---|---|
| `DexEncryptor.java` | AES/CBC/PKCS5Padding 加密，128 位密钥，随机 IV 前置于密文 |
| `ManifestEditor.java` | 解析 AXML 二进制格式（兼容 UTF-8/UTF-16），通过 ResourceID 精确定位 `android:name` 并替换 |
| `Main.java` | 从 APK 提取 DEX 和清单 → 加密 → 编辑清单 → 输出加密 DEX + 修改后清单 + 配置文件 |

### Stub-App（设备端 Java 层）

| 文件 | 功能 |
|---|---|
| `ProxyApplication.java` | 壳入口，负责 DEX 解密加载和 Application 生命周期切换 |
| `RefInvoke.java` | 通用反射工具 + ActivityThread/LoadedApk/DexPathList 专用操作 |

### Stub-App（设备端 Native 层）

| 文件 | 功能 |
|---|---|
| `guard.cpp` | 自实现 AES-128-CBC 解密引擎（零外部依赖）+ JNI 动态注册 |
| `anti_debug.cpp` | 五重防护：ptrace 占位 / TracerPid 轮询 / 模拟器检测 / Frida 端口探测 / Frida 内存扫描 |

## 安全特性

### 加密

- AES-128-CBC + PKCS7，每次加密使用随机 IV
- Native 层自实现 AES（无 OpenSSL 依赖），不暴露标准加密库符号
- 解密后立即 `memset` 清零明文缓冲区和轮密钥

### 反调试

| 防护层 | 机制 |
|---|---|
| ptrace 占位 | `PTRACE_TRACEME` 抢占调试槽，阻止 GDB/LLDB 附加 |
| TracerPid 轮询 | 独立线程每 800ms 扫描 `/proc/self/status`，检测运行时附加 |
| Frida 端口探测 | 尝试连接 `127.0.0.1:27042`（Frida 默认端口） |
| Frida 内存扫描 | 独立线程每 1.5s 扫描 `/proc/self/maps`，匹配 `frida-agent` / `frida-gadget` |
| 模拟器检测 | 探测 18 个特征文件路径 + `/proc/cpuinfo` hypervisor 标记 |

### 静默崩溃

检测到任何威胁时，通过空函数指针触发 `SIGSEGV`，表现为随机原生崩溃，不暴露保护意图。

### 日志安全

运行时壳程序 **零日志输出**（无 `Log.*`、无 `__android_log_print`），不泄露任何逻辑线索。

### 符号隐藏

- JNI 使用 `RegisterNatives` 动态注册，不暴露 `Java_com_shell_stub_*` 符号
- CMake 启用 `-fvisibility=hidden`，仅导出 `JNI_OnLoad`

### Android 14+ 兼容

- API 26+ 优先使用 `InMemoryDexClassLoader` 纯内存加载，天然符合只读策略
- 磁盘加载路径在写入后立即 `setReadOnly()`，兼容 Android 14 的动态代码安全限制

## 快速开始

### 1. 编译加壳工具

```bash
cd Protector-Tool
bash build.sh
```

### 2. 对 APK 执行加壳

```bash
java -cp build com.shell.protector.Main original.apk output/
```

输出：

| 文件 | 说明 |
|---|---|
| `output/classes.dex.enc` | 加密后的原始 DEX |
| `output/AndroidManifest.xml` | 已替换 Application 入口的二进制清单 |
| `output/shell_config.properties` | 原始 Application 类名配置 |

### 3. 组装最终 APK

将以下文件放入壳 APK 对应位置：

```
壳 APK/
├── assets/
│   ├── classes.dex.enc              ← 加密后的 DEX
│   └── shell_config.properties      ← 配置文件
├── AndroidManifest.xml              ← 修改后的清单
├── classes.dex                      ← Stub-App 编译产物
└── lib/
    └── armeabi-v7a/
        └── libguard.so              ← Native 编译产物
```

### 4. 签名并安装

```bash
apksigner sign --ks your.keystore output.apk
adb install output.apk
```

## 构建要求

| 组件 | 版本要求 |
|---|---|
| JDK | 17+ |
| Android NDK | r21+ |
| CMake | 3.18.1+ |
| Android Gradle Plugin | 7.0+（如使用 Gradle 构建 Stub-App） |

## 技术栈

- **加密算法**: AES-128-CBC / PKCS7 — Java（javax.crypto）+ C++（自实现）
- **清单编辑**: 自实现 AXML 二进制解析器（无第三方依赖）
- **DEX 加载**: InMemoryDexClassLoader (API 26+) / DexClassLoader (legacy)
- **ClassLoader 注入**: 反射操作 BaseDexClassLoader.pathList.dexElements
- **Application 替换**: 反射 ActivityThread / LoadedApk / ContextImpl
- **JNI**: 动态注册 (RegisterNatives) + JNI_OnLoad 自动初始化
- **反调试**: ptrace / procfs / socket / mmap 多维检测

## 免责声明

本项目仅供安全研究和学习用途。请勿将其用于任何违反法律法规的行为。使用者应自行承担所有风险和法律责任。
