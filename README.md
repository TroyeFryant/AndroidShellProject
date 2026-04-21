# Android Shell Project — 基于主动反调试和动态 DEX 加密解密机制的 Android 加壳框架

一套完整的 Android APK 加壳保护方案，涵盖 **PC 端加壳工具**、**设备端壳程序（Java + Native C++）**、**Web 管理后端** 和 **可视化前端**。

核心特性：每包随机密钥 AES-128-CBC 加密 + HMAC-SHA256 完整性校验、13 层主动反调试防护、解密后内存清理、DEX 头部校验、性能基准测试，以及一键上传加固签名下载的 Web 管理平台。

---

## 项目结构

```
AndroidShellProject/
│
├── Protector-Tool/                          # PC 端加壳工具 (Java 17)
│   ├── build.sh                             # 编译脚本
│   └── src/com/shell/protector/
│       ├── DexEncryptor.java                # AES-128-CBC 加密 + HMAC-SHA256 + 每包随机密钥
│       ├── ManifestEditor.java              # AXML 二进制清单编辑器
│       └── Main.java                        # 集成主入口（密钥生成 + 配置写入）
│
├── Stub-App/                                # 设备端壳程序
│   ├── build.sh                             # Java → classes.dex (d8)
│   ├── build_native.sh                      # C++ → libguard.so (NDK/CMake)
│   ├── libs/                                # 编译产物: 各 ABI 的 libguard.so
│   │   ├── arm64-v8a/
│   │   ├── armeabi-v7a/
│   │   ├── x86_64/
│   │   └── x86/
│   ├── src/com/shell/stub/
│   │   ├── ProxyApplication.java            # 壳入口 Application（解密/加载/反调试/基准测试）
│   │   └── utils/
│   │       └── RefInvoke.java               # 反射工具类
│   └── app/src/main/cpp/
│       ├── CMakeLists.txt                   # NDK 构建配置
│       ├── anti_debug.h                     # 反调试头文件（13 层声明）
│       ├── anti_debug.cpp                   # 10 层 Native 反调试体系
│       └── guard.cpp                        # C++ AES 解密 + SHA256 + HMAC + JNI
│
├── Shell-Web-Server/                        # 后端管理系统 (Python/FastAPI)
│   ├── main.py                              # API 路由 + 管理后台接口 (端口 1078)
│   ├── task_manager.py                      # 异步任务调度 + 持久化恢复
│   ├── requirements.txt                     # Python 依赖
│   ├── storage/                             # 运行时数据
│   │   ├── raw/                             # 上传的原始 APK
│   │   ├── output/                          # 加固后的 APK
│   │   ├── logs/                            # 每个任务的执行日志
│   │   └── meta/                            # 任务元数据 (JSON)
│   └── utils/
│       ├── shell_wrapper.py                 # Java 工具调用 / 重打包 / 对齐 / 签名
│       └── shell.jks                        # 默认签名密钥库
│
├── Shell-Frontend/                          # 前端界面 (单页应用 + Tailwind CSS)
│   ├── index.html                           # 四标签页统一布局
│   └── app.js                               # 交互逻辑（加固/历史/防护/系统）
│
├── graduation.md                            # 毕业设计论文稿
└── README.md
```

---

## 工作原理

### 整体加固流程

```
原始 APK
    │
    ▼
┌───────────────────────────────────────────────────────┐
│                Protector-Tool (PC 端)                   │
│                                                       │
│  1. 生成 16 字节随机密钥 (SecureRandom)                   │
│  2. 提取全部 classes*.dex → 打包为单一 blob               │
│  3. AES-128-CBC 加密 → HMAC-SHA256 完整性签名             │
│     → classes.dex.enc ( IV‖Ciphertext‖HMAC )           │
│  4. 解析二进制 AndroidManifest.xml                       │
│     • 注入/替换 android:name → ProxyApplication          │
│     • 移除 appComponentFactory 属性                      │
│     • 按 resource ID 排序保证 AXML 合法                   │
│  5. 写入配置 shell_config.properties                     │
│     (原始 Application 名 + Base64 编码的密钥)              │
└───────────────────────────────────────────────────────┘
    │
    ▼
┌───────────────────────────────────────────────────────┐
│                 重打包 (Python 后端)                      │
│                                                       │
│  1. 替换原始 DEX → 壳程序 stub classes.dex                │
│  2. 注入 assets/classes.dex.enc + config                │
│  3. 注入 lib/{abi}/libguard.so (按原 APK ABI)            │
│  4. zipalign 对齐 (SO 4096 / 其他 4 字节)                 │
│  5. apksigner v2/v3 签名                                │
└───────────────────────────────────────────────────────┘
    │
    ▼
加固后 APK (安装到设备)
    │
    ▼
┌───────────────────────────────────────────────────────┐
│             Stub-App 运行时 (设备端)                      │
│                                                       │
│  ① static {} → System.loadLibrary("guard")             │
│     └→ JNI_OnLoad: 动态注册 + 启动 10 层 Native 反调试    │
│                                                       │
│  ② attachBaseContext:                                   │
│     ├─ Java 层调试检测 (3 层)                              │
│     ├─ 从 config 读取 Base64 密钥                         │
│     ├─ Native decryptDex() (C++ AES + HMAC 验证)         │
│     │   失败时回退 → Java AES + HMAC 解密                  │
│     ├─ 时间差反调试检测                                    │
│     ├─ DEX 头部校验 (Magic + Adler32)                     │
│     ├─ 解密后内存清理 (Arrays.fill + memset + madvise)     │
│     ├─ 解析多 DEX blob → ClassLoader 注入                  │
│     └─ 性能基准测试记录                                    │
│                                                       │
│  ③ onCreate:                                            │
│     ├─ 实例化原始 Application 并绑定 Context                │
│     ├─ 替换 ActivityThread/LoadedApk 中的引用              │
│     └─ 调用原始 Application.onCreate()                    │
└───────────────────────────────────────────────────────┘
```

### Web 管理平台

```
┌──────────────────────┐     HTTP      ┌──────────────────────────┐
│   单页应用 (SPA)       │ ──────────→  │   FastAPI 后端 (:1078)    │
│                      │              │                          │
│ 四标签页左侧导航：      │  /api/       │ • 接收 APK                │
│ • APK 加固           │   upload     │ • 后台异步调用              │
│ • 历史记录           │   status     │   Protector-Tool (Java)   │
│ • 防护体系           │   tasks      │ • 重打包 + 对齐 + 签名      │
│ • 系统状态           │   admin/info │ • 防护体系元信息 API        │
│                      │              │ • 自动清理过期文件          │
│                      │              │ • 持久化任务记录            │
└──────────────────────┘              └──────────────────────────┘
```

---

## 安全特性

### 加密方案

| 特性 | 说明 |
|------|------|
| 算法 | AES-128-CBC + PKCS5Padding |
| 密钥策略 | **每包随机密钥** — `SecureRandom` 生成 16 字节，Base64 存入配置 |
| 完整性校验 | **HMAC-SHA256 (Encrypt-then-MAC)** — 防篡改、防截断 |
| 密文格式 | `[IV(16B)] ‖ [Ciphertext] ‖ [HMAC-SHA256(32B)]` |
| 多 DEX | 所有 `classes*.dex` 打包为单一 blob 后整体加密 |
| Native 实现 | C++ 自实现 AES + SHA-256 + HMAC（零外部依赖），不暴露标准加密库符号 |
| DEX 校验 | 解密后验证 Magic (`dex\n`) + Adler32 Checksum |
| 内存清理 | Java `Arrays.fill(0)` + C++ `memset` + `madvise(MADV_DONTNEED)` |
| 密钥存储 | `shell_config.properties` (Base64) |
| 设备绑定 | HMAC-SHA256(key ‖ ANDROID_ID ‖ APK签名哈希) — 可选能力 |
| Java 回退 | Native 库加载失败时自动降级为 Java AES + HMAC 解密 |

### 反调试（13 层防护）

#### Native 层（10 层）

| # | 防护层 | 类型 | 运行模式 | 机制 |
|---|--------|------|----------|------|
| 1 | ptrace 自占位 | 进程级 | 启动时 | `PTRACE_TRACEME` 抢占调试槽 + `TracerPid` 双重验证，兼容 MIUI SELinux |
| 2 | TracerPid 后台轮询 | 进程级 | 后台线程 | 独立线程每 800ms 读取 `/proc/self/status`，防御延迟附加 |
| 3 | 双进程 ptrace 交叉守护 | 进程级 | 独立进程 | fork 子进程互相 `PTRACE_ATTACH`，心跳存活检测 |
| 4 | 模拟器环境检测 | 环境级 | 启动时 | 18+ 特征文件（QEMU/VBox/Nox） + `/proc/cpuinfo` 虚拟化标记 |
| 5 | Frida 即时检测 | 工具级 | 启动时 | TCP 27042 端口 + D-Bus 协议探测 + `/proc/self/maps` 扫描 + 线程名匹配 |
| 6 | Frida 持续监控 | 工具级 | 后台线程 | 独立线程每 1.5s 执行三维 Frida 检测（端口/内存映射/线程名） |
| 7 | GOT/PLT Hook 检测 | 代码级 | 启动时 | 校验 `fopen`/`ptrace`/`open`/`read`/`mmap` 地址是否在 `libc.so` 范围内 |
| 8 | Root/Magisk/Xposed 检测 | 环境级 | 启动时 | 13+ 特征文件 + `/proc/self/maps` 扫描 XposedBridge/riru/edxposed/lspd |
| 9 | .text 段 CRC32 校验 | 代码级 | 后台线程 | 解析 ELF 定位 `.text` 段，计算 CRC32 基准值，每 3s 复验 |
| 10 | 时间差反调试 | 代码级 | 关键段 | `clock_gettime(CLOCK_MONOTONIC)` 在解密前后设检测点，阈值 800ms |

#### Java 层（3 层）

| # | 防护层 | 机制 |
|---|--------|------|
| 11 | JDWP 调试器检测 | `Debug.isDebuggerConnected()` |
| 12 | FLAG_DEBUGGABLE 检测 | `ApplicationInfo.flags & FLAG_DEBUGGABLE` |
| 13 | waitingForDebugger 检测 | `Debug.waitingForDebugger()` |

### 其他安全设计

- **静默崩溃**: 检测到威胁时通过空函数指针触发 SIGSEGV，伪装为随机原生崩溃，不暴露保护逻辑
- **零日志**: 运行时壳程序无任何 `Log` 或 `printf` 输出
- **符号隐藏**: JNI 动态注册 + `-fvisibility=hidden`，仅导出 `JNI_OnLoad`
- **ROM 兼容**: 移除 `appComponentFactory` 属性，避免 MIUI 等 ROM 因找不到 `CoreComponentFactory` 而跳过壳 Application
- **Android 14+**: `InMemoryDexClassLoader` 纯内存加载 + 磁盘文件自动 `setReadOnly()`
- **性能基准**: `System.nanoTime()` 全链路计时，记录各阶段耗时

---

## 快速开始

### 环境要求

| 组件 | 版本 | 用途 |
|------|------|------|
| JDK | 17+ | 编译 Protector-Tool |
| Python | 3.10+ | 运行 Web 后端 |
| Android SDK | API 21+ (`android.jar`, `d8`) | 编译壳程序 stub DEX |
| Android NDK | r25+（含 CMake） | 编译 `libguard.so` |

### 1. 编译加壳工具（Protector-Tool）

```bash
cd Protector-Tool && bash build.sh
```

编译输出位于 `Protector-Tool/build/`。

### 2. 编译壳程序 DEX（Stub-App Java 层）

```bash
cd Stub-App && bash build.sh
```

编译输出 `Stub-App/build/classes.dex`，需要 `$ANDROID_HOME` 指向 Android SDK。

### 3. 编译 Native 反调试库（Stub-App C++ 层）

```bash
cd Stub-App && bash build_native.sh
```

编译输出到 `Stub-App/libs/` 下各 ABI 目录（`arm64-v8a`、`armeabi-v7a`、`x86_64`、`x86`）。

### 4. 启动 Web 管理系统

```bash
cd Shell-Web-Server
pip install -r requirements.txt
python main.py
```

浏览器访问 `http://localhost:1078`，左侧导航切换四个功能页面：

| 标签页 | 功能 |
|--------|------|
| APK 加固 | 拖拽上传 APK，实时进度条，加固完成后下载 |
| 历史记录 | 全部加固任务列表，支持下载、删除、一键清理 |
| 防护体系 | 可视化展示 13 层反调试 + 加密机制详情 |
| 系统状态 | 组件就绪状态、构建工具链、Native 库大小、源文件统计 |

### 5. 命令行加壳（不使用 Web 界面）

```bash
java -cp Protector-Tool/build com.shell.protector.Main <input.apk> <output_dir>
```

加壳后产物位于 `<output_dir>/`，包含修改后的 `AndroidManifest.xml`、`classes.dex.enc` 和 `shell_config.properties`。

### 6. 配置 APK 签名

设置以下环境变量后重启后端，加固完成后自动签名：

```bash
export KEYSTORE_PATH=/path/to/your.keystore
export KEYSTORE_PASS=your_password
export KEY_ALIAS=your_alias
```

未配置时，后端使用内置的 `shell.jks` 默认密钥库签名。后端优先使用 `apksigner`（v2/v3 签名），未找到时降级为 `jarsigner`（v1 签名）。

---

## Web API 参考

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/upload` | 上传 APK，返回 `task_id` 和文件信息 |
| GET | `/api/status/{task_id}` | 查询加固进度 |
| GET | `/api/download/{task_id}` | 下载加固后的 APK |
| GET | `/api/logs/{task_id}` | 获取加固执行日志 |
| GET | `/api/tasks` | 列出所有历史任务（含磁盘恢复） |
| DELETE | `/api/tasks/{task_id}` | 删除单个任务及关联文件 |
| DELETE | `/api/tasks` | 一键清理所有任务 |
| GET | `/api/admin/info` | 框架防护能力、组件状态、统计数据 |

### 上传响应

```json
{
  "task_id": "a1b2c3d4e5f6",
  "filename": "example.apk",
  "size": 26214400
}
```

### 状态查询响应

```json
{
  "task_id": "a1b2c3d4e5f6",
  "filename": "example.apk",
  "status": "processing",
  "progress": 70,
  "message": "正在打包输出文件...",
  "created_at": 1710400000.0
}
```

`status` 取值：`pending` → `processing` → `completed` / `failed`

### 管理后台接口响应（摘要）

```json
{
  "framework": { "name": "Android Shell Protector", "version": "2.0" },
  "encryption": {
    "algorithm": "AES-128-CBC",
    "key_mode": "每包随机密钥 (SecureRandom, 16 bytes)",
    "integrity": "HMAC-SHA256 (Encrypt-then-MAC)"
  },
  "anti_debug": {
    "native_layers": [ "...10 层..." ],
    "java_layers": [ "...3 层..." ],
    "response": "空函数指针触发 SIGSEGV 静默崩溃"
  },
  "components": { "protector_tool": {}, "stub_app": {}, "native": {}, "web_server": {} },
  "stats": { "total_code_lines": "...", "total_tasks": "..." },
  "tools": { "java": true, "apksigner": true, "zipalign": true }
}
```

---

## 核心模块说明

### Protector-Tool (PC 端)

| 文件 | 职责 |
|------|------|
| `DexEncryptor.java` | `SecureRandom` 生成每包随机密钥；AES-128-CBC 加密；HMAC-SHA256 完整性签名；多 DEX 打包为单一 blob（4 字节长度前缀 + DEX 数据） |
| `ManifestEditor.java` | 解析二进制 AXML 格式；注入/替换 `android:name`（按 resource ID 排序插入）；移除 `appComponentFactory`；重建字符串池 |
| `Main.java` | 集成入口：生成随机密钥 → 提取全部 DEX → 加密 → 修改清单 → 生成配置文件（含 Base64 密钥） |

### Stub-App (设备端)

| 文件 | 职责 |
|------|------|
| `ProxyApplication.java` | 壳入口 Application；Java 层 3 层调试检测；从 config 读取密钥并解密；DEX 头部校验（Magic + Adler32）；解密后内存清理；多 DEX 加载（内存/磁盘双模式）；ClassLoader 注入；原始 Application 生命周期代理；性能基准测试计时 |
| `RefInvoke.java` | 反射工具类；封装 `getField` / `setField` / `invoke`，支持访问 `mPackageInfo`、`DexPathList` 等私有字段 |
| `guard.cpp` | C++ 自实现 AES-128-CBC + SHA-256 + HMAC-SHA256（零外部依赖）；HMAC 验证后解密；常量时间比较防侧信道；密钥/明文内存清零；时间差检测 JNI 方法；`JNI_OnLoad` 动态注册并触发反调试 |
| `anti_debug.cpp` | 10 层 Native 反调试：ptrace 占位、TracerPid 轮询、双进程交叉守护、模拟器检测、Frida 三维检测（端口/内存/线程名）、GOT/PLT Hook 检测、Root/Magisk/Xposed 检测、.text 段 CRC32 完整性校验、时间差检测；所有检测触发静默崩溃 |

### Shell-Web-Server (后端)

| 文件 | 职责 |
|------|------|
| `main.py` | FastAPI 路由；文件上传、状态查询、下载、日志、任务列表/清理 API；管理后台元信息接口 `/api/admin/info`（防护层级、组件状态、统计数据） |
| `task_manager.py` | 异步任务生命周期管理；启动时从磁盘恢复历史任务；元数据持久化（JSON） |
| `shell_wrapper.py` | 跨语言调用：`subprocess` 执行 Java 加壳工具 → APK 重打包（注入 stub DEX + 加密 DEX + libguard.so） → `zipalign` 对齐 → `apksigner` 签名；自动清理 24h 过期文件 |

### Shell-Frontend (前端)

| 文件 | 职责 |
|------|------|
| `index.html` | 单页应用；左侧导航四标签页（加固/历史/防护/系统）；Tailwind CSS 暗色主题；内联标签切换脚本确保缓存安全 |
| `app.js` | 加固流程（上传→轮询→下载）；历史任务管理（列表/删除/批量清理）；防护体系数据可视化（13 层反调试 + 加密机制）；系统状态展示（组件/工具链/源码统计） |

---

## 兼容性

| 特性 | 支持范围 |
|------|---------|
| 最低 Android API | 21 (Android 5.0) |
| DEX 加载方式 | API >= 26: `InMemoryDexClassLoader`（纯内存） / API < 26: `DexClassLoader` |
| Android 14+ | 自动设置 DEX 文件只读权限 |
| 多 DEX | 支持任意数量的 `classes*.dex` |
| ABI | `arm64-v8a` / `armeabi-v7a` / `x86_64` / `x86` |
| ROM 兼容 | 移除 `appComponentFactory`，兼容 MIUI 等定制系统 |
| 签名方案 | 优先 apksigner (v2/v3)，降级 jarsigner (v1) |

---

## 注意事项

1. **首次使用前必须编译**：依次运行 `Protector-Tool/build.sh`、`Stub-App/build.sh`、`Stub-App/build_native.sh`
2. **签名密钥**: 生产环境请替换 `shell.jks` 为自有密钥库，通过环境变量配置
3. **每包随机密钥**: 加壳工具会自动为每个 APK 生成独立密钥，密钥以 Base64 形式存入 `shell_config.properties`
4. **任务持久化**: 任务元数据存储在 `storage/meta/`，服务器重启后自动恢复历史记录
5. **自动清理**: 后端每 6 小时自动清理 `storage/` 下超过 24 小时的临时文件
6. **设备绑定**: `deriveDeviceKey()` 已实现为可选能力，需手动启用

---

## 免责声明

本项目仅供安全研究和学习用途。请勿用于任何违反法律法规的行为。使用者应自行承担因使用本项目而产生的任何法律责任。
