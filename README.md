# Android Shell Project — Android DEX 加壳保护框架

一套完整的 Android APK 加壳保护方案，涵盖 **PC 端加壳工具**、**设备端壳程序（Java + Native）**、**Web 管理后端** 和 **可视化前端**，支持一键上传加固、签名、下载。

---

## 项目结构

```
AndroidShellProject/
│
├── Protector-Tool/                          # PC 端加壳工具 (Java 17)
│   ├── build.sh                             # 编译脚本
│   └── src/com/shell/protector/
│       ├── DexEncryptor.java                # AES-128-CBC 多 DEX 加密
│       ├── ManifestEditor.java              # AXML 二进制清单编辑器
│       └── Main.java                        # 集成主入口
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
│   │   ├── ProxyApplication.java            # 壳入口 Application
│   │   └── utils/
│   │       └── RefInvoke.java               # 反射工具类
│   └── app/src/main/cpp/
│       ├── CMakeLists.txt                   # NDK 构建配置
│       ├── anti_debug.h                     # 反调试头文件
│       ├── anti_debug.cpp                   # 反调试 / 反 Frida / 模拟器检测
│       └── guard.cpp                        # AES-128-CBC 解密 + JNI 动态注册
│
├── Shell-Web-Server/                        # 后端管理系统 (Python/FastAPI)
│   ├── main.py                              # API 路由入口 (端口 1078)
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
├── Shell-Frontend/                          # 前端界面 (HTML + Tailwind CSS)
│   ├── index.html                           # 上传 / 进度 / 下载 / 历史记录
│   └── app.js                               # 交互逻辑 (轮询/删除/清理)
│
└── README.md
```

---

## 工作原理

### 整体加固流程

```
原始 APK
    │
    ▼
┌────────────────────────────────────────────────────┐
│               Protector-Tool (PC 端)                │
│                                                    │
│  1. 提取全部 classes*.dex                            │
│  2. 多 DEX 打包为一个 blob → AES-128-CBC 加密         │
│     → classes.dex.enc (IV 前缀 + 密文)               │
│  3. 解析二进制 AndroidManifest.xml                    │
│     • 注入/替换 android:name → ProxyApplication      │
│     • 移除 appComponentFactory 属性                  │
│     • 按 resource ID 排序保证 AXML 合法               │
│  4. 记录原始 Application 类名                         │
│     → shell_config.properties                       │
└────────────────────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────────────────────┐
│               重打包 (Python 后端)                    │
│                                                    │
│  1. 替换原始 DEX → 壳程序 stub classes.dex            │
│  2. 注入 assets/classes.dex.enc + config            │
│  3. 注入 lib/{abi}/libguard.so (按原 APK ABI)        │
│  4. zipalign 对齐 (SO 4096 / 其他 4 字节)             │
│  5. apksigner v2/v3 签名                            │
└────────────────────────────────────────────────────┘
    │
    ▼
加固后 APK (安装到设备)
    │
    ▼
┌────────────────────────────────────────────────────┐
│           Stub-App 运行时 (设备端)                    │
│                                                    │
│  ① 类加载时触发 static {} → System.loadLibrary       │
│     └→ JNI_OnLoad: 注册 native 方法 + 启动反调试      │
│                                                    │
│  ② attachBaseContext:                               │
│     ├─ initAntiDebug()                              │
│     │   └→ ptrace 占位 / TracerPid / Frida / 模拟器  │
│     ├─ 读取 assets/classes.dex.enc                   │
│     ├─ native decryptDex() (C++ AES 解密)            │
│     │   失败时回退 → Java AES 解密                    │
│     ├─ 解析多 DEX blob (4字节长度 + DEX数据)           │
│     ├─ API ≥ 26: InMemoryDexClassLoader (纯内存)     │
│     │  API < 26: DexClassLoader (写 code_cache)      │
│     └─ 反射注入 dexElements 到当前 ClassLoader         │
│                                                    │
│  ③ onCreate:                                        │
│     ├─ 反射读取原始 Application 类名                   │
│     ├─ 实例化原始 Application 并绑定 Context           │
│     ├─ 替换 ActivityThread/LoadedApk 中的引用          │
│     └─ 调用原始 Application.onCreate()                │
└────────────────────────────────────────────────────┘
```

### Web 管理平台

```
┌────────────────┐     HTTP      ┌────────────────────────┐
│   浏览器前端     │ ──────────→  │   FastAPI 后端 (:1078)  │
│                │              │                        │
│ • 拖拽上传 APK  │  POST /api/  │ • 接收 APK             │
│ • 实时进度条    │   upload     │ • 后台异步调用           │
│ • 下载加固产物  │              │   Protector-Tool (Java) │
│ • 历史任务列表  │  GET /api/   │ • 重打包 + 对齐 + 签名  │
│ • 一键清理     │   status     │ • 自动清理过期文件       │
│               │              │ • 持久化任务记录         │
└────────────────┘              └────────────────────────┘
```

---

## 安全特性

### 加密方案

| 特性 | 说明 |
|------|------|
| 算法 | AES-128-CBC + PKCS7Padding |
| IV | 每次加密随机生成 16 字节 IV，前缀存储于密文头部 |
| 多 DEX | 所有 `classes*.dex` 打包为单一 blob 后整体加密 |
| Native 实现 | C++ 自实现 AES（零外部依赖），不暴露标准加密库符号 |
| 安全清理 | 解密后立即 `memset` 清零明文缓冲区和轮密钥 |
| Java 回退 | Native 库加载失败时自动降级为 Java AES 解密 |

### 反调试（五重防护）

| 防护层 | 机制 | 触发方式 |
|--------|------|----------|
| ptrace 占位 | `PTRACE_TRACEME` 抢占调试槽，阻止 GDB/LLDB | 配合 TracerPid 双重验证，避免 MIUI 等 ROM 误杀 |
| TracerPid 轮询 | 独立线程每 800ms 扫描 `/proc/self/status` | 检测 TracerPid > 0 |
| Frida 端口探测 | 尝试连接 `127.0.0.1:27042`（Frida 默认端口） | 连接成功即触发 |
| Frida 内存扫描 | 独立线程每 1.5s 扫描 `/proc/self/maps` | 匹配 `frida-agent` / `frida-gadget` |
| 模拟器检测 | 18 个特征文件 + `/proc/cpuinfo` hypervisor 标记 | 检测到模拟器特征即触发 |

### 其他安全设计

- **静默崩溃**: 检测到威胁时通过空函数指针触发 SIGSEGV，伪装为随机原生崩溃，不暴露保护逻辑
- **零日志**: 运行时壳程序无任何 `Log` 或 `printf` 输出
- **符号隐藏**: JNI 动态注册 + `-fvisibility=hidden`，仅导出 `JNI_OnLoad`
- **ROM 兼容**: 移除 `appComponentFactory` 属性，避免 MIUI 等 ROM 因找不到 `CoreComponentFactory` 而跳过壳 Application
- **Android 14+**: `InMemoryDexClassLoader` 纯内存加载 + 磁盘文件自动 `setReadOnly()`

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

浏览器访问 `http://localhost:1078`，拖拽 APK 文件即可一键加固。

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

### 任务列表响应

```json
{
  "tasks": [
    {
      "task_id": "a1b2c3d4e5f6",
      "filename": "example.apk",
      "status": "completed",
      "progress": 100,
      "message": "加固完成",
      "created_at": 1710400000.0,
      "has_output": true,
      "output_size": 26285263
    }
  ]
}
```

---

## 核心模块说明

### Protector-Tool (PC 端)

| 文件 | 职责 |
|------|------|
| `DexEncryptor.java` | AES-128-CBC 加密；支持多 DEX 打包为单一 blob（4 字节长度前缀 + DEX 数据，循环拼接） |
| `ManifestEditor.java` | 解析二进制 AXML 格式；注入/替换 `android:name`（按 resource ID 排序插入）；移除 `appComponentFactory`；重建字符串池 |
| `Main.java` | 集成入口：提取全部 DEX → 加密 → 修改清单 → 生成配置文件 |

### Stub-App (设备端)

| 文件 | 职责 |
|------|------|
| `ProxyApplication.java` | 壳入口 Application；负责解密、多 DEX 加载（内存/磁盘双模式）、ClassLoader 注入、原始 Application 生命周期代理 |
| `RefInvoke.java` | 反射工具类；封装 `getField` / `setField` / `invoke`，支持访问 `mPackageInfo`、`DexPathList` 等私有字段 |
| `guard.cpp` | C++ AES-128-CBC 自实现解密；`JNI_OnLoad` 动态注册 native 方法并触发反调试初始化 |
| `anti_debug.cpp` | 五重反调试：ptrace 占位、TracerPid 轮询、Frida 端口探测、Frida 内存扫描、模拟器检测；所有检测触发静默崩溃 |

### Shell-Web-Server (后端)

| 文件 | 职责 |
|------|------|
| `main.py` | FastAPI 路由；文件上传、状态查询、下载、日志、任务列表和清理 API |
| `task_manager.py` | 异步任务生命周期管理；启动时从磁盘恢复历史任务；元数据持久化（JSON） |
| `shell_wrapper.py` | 跨语言调用：`subprocess` 执行 Java 加壳工具 → APK 重打包（注入 stub DEX + 加密 DEX + libguard.so） → `zipalign` 对齐 → `apksigner` 签名；自动清理 24h 过期文件 |

### Shell-Frontend (前端)

| 文件 | 职责 |
|------|------|
| `index.html` | Tailwind CSS 暗色主题 UI；拖拽上传区域、进度条、历史记录表格、一键清理按钮 |
| `app.js` | 上传 APK → 轮询进度（2s 间隔）→ 完成后启用下载；历史任务加载/删除/批量清理 |

---

## 加固流程详细步骤

以 Web 管理系统一键加固为例，完整执行链路：

```
用户拖拽上传 APK
    │
    ▼
POST /api/upload → 保存到 storage/raw/{task_id}.apk
    │                写入 meta/{task_id}.json (原始文件名)
    ▼
asyncio.create_task(process_task)
    │
    ├─① run_protector()
    │     └→ java -cp ... Main.java input.apk output_dir/
    │         ├─ 加密 → output_dir/classes.dex.enc
    │         ├─ 清单 → output_dir/AndroidManifest.xml
    │         └─ 配置 → output_dir/shell_config.properties
    │
    ├─② repackage_apk()
    │     ├─ 复制原 APK 非 META-INF / 非 DEX 文件
    │     ├─ 替换 DEX → stub classes.dex
    │     ├─ 注入 assets/classes.dex.enc + config
    │     └─ 注入 lib/{abi}/libguard.so (按原 APK 架构)
    │
    ├─③ zipalign()
    │     └─ SO 文件 4096 字节对齐 / 其他 4 字节对齐
    │
    └─④ sign_apk()
          └─ apksigner sign --ks ... (v2/v3)
              或 jarsigner (v1 降级)
    │
    ▼
status → completed → 前端轮询到完成 → 启用下载按钮
```

---

## 兼容性

| 特性 | 支持范围 |
|------|---------|
| 最低 Android API | 21 (Android 5.0) |
| DEX 加载方式 | API ≥ 26: `InMemoryDexClassLoader`（纯内存） / API < 26: `DexClassLoader` |
| Android 14+ | 自动设置 DEX 文件只读权限 |
| 多 DEX | 支持任意数量的 `classes*.dex` |
| ABI | `arm64-v8a` / `armeabi-v7a` / `x86_64` / `x86` |
| ROM 兼容 | 移除 `appComponentFactory`，兼容 MIUI 等定制系统 |
| 签名方案 | 优先 apksigner (v2/v3)，降级 jarsigner (v1) |

---

## 注意事项

1. **首次使用前必须编译**：依次运行 `Protector-Tool/build.sh`、`Stub-App/build.sh`、`Stub-App/build_native.sh`
2. **签名密钥**: 生产环境请替换 `shell.jks` 为自有密钥库，通过环境变量配置
3. **加密密钥**: 当前使用硬编码对称密钥，生产环境建议改为随机生成并安全分发
4. **任务持久化**: 任务元数据存储在 `storage/meta/`，服务器重启后自动恢复历史记录
5. **自动清理**: 后端每 6 小时自动清理 `storage/` 下超过 24 小时的临时文件

---

## 免责声明

本项目仅供安全研究和学习用途。请勿用于任何违反法律法规的行为。使用者应自行承担因使用本项目而产生的任何法律责任。
