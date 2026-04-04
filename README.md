# Android Shell Project — Android DEX 加壳框架

一套完整的 Android APK 加壳保护方案，包含 **PC 端加壳工具**、**设备端壳程序** 和 **Web 管理系统**。

## 项目结构

```
AndroidShellProject/
│
├── Protector-Tool/                          # PC 端加壳工具 (Java 17)
│   ├── build.sh
│   └── src/com/shell/protector/
│       ├── DexEncryptor.java                # AES-128-CBC DEX 加密
│       ├── ManifestEditor.java              # AXML 二进制清单编辑
│       └── Main.java                        # 集成主入口
│
├── Stub-App/                                # 设备端壳程序
│   ├── src/com/shell/stub/
│   │   ├── ProxyApplication.java            # 壳入口 Application
│   │   └── utils/
│   │       └── RefInvoke.java               # 反射工具类
│   └── app/src/main/cpp/
│       ├── CMakeLists.txt                   # NDK 构建 → libguard.so
│       ├── anti_debug.h / anti_debug.cpp    # 反调试 / 反 Frida / 模拟器检测
│       └── guard.cpp                        # AES 解密 + JNI 注册
│
├── Shell-Web-Server/                        # 后端管理系统 (Python/FastAPI)
│   ├── main.py                              # API 路由入口
│   ├── task_manager.py                      # 异步任务调度
│   ├── requirements.txt
│   ├── storage/                             # 上传/输出/日志存储
│   │   ├── raw/
│   │   ├── output/
│   │   └── logs/
│   └── utils/
│       └── shell_wrapper.py                 # Java 工具调用 / 签名 / 清理
│
├── Shell-Frontend/                          # 前端界面 (HTML + Tailwind CSS)
│   ├── index.html                           # 上传 / 进度 / 下载界面
│   └── app.js                              # 交互逻辑
│
└── README.md
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
 │     └─→ JNI_OnLoad: 注册 native + 启动反调试             │
 │                                                          │
 │  2. attachBaseContext:                                    │
 │     ├─ initAntiDebug()  → ptrace/TracerPid/Frida/模拟器  │
 │     ├─ 读取 assets/classes.dex.enc                       │
 │     ├─ native decryptDex() → AES-128-CBC 解密            │
 │     ├─ API≥26: InMemoryDexClassLoader (纯内存)           │
 │     │  API<26: DexClassLoader (code_cache, 只读)         │
 │     └─ 注入 dexElements 到当前 ClassLoader               │
 │                                                          │
 │  3. onCreate:                                            │
 │     ├─ 反射实例化原始 Application                         │
 │     ├─ 替换 ActivityThread/LoadedApk 中所有引用           │
 │     └─ 调用原始 Application.onCreate()                   │
 └──────────────────────────────────────────────────────────┘

 ┌──────────────────────────────────────────────────────────┐
 │               Web 管理系统: 一键加固平台                   │
 │                                                          │
 │  浏览器 ──→ 拖拽上传 APK ──→ FastAPI 后端                 │
 │                                   ↓                      │
 │                          subprocess 调用                  │
 │                          Protector-Tool                   │
 │                                   ↓                      │
 │                          实时日志 + 进度条                 │
 │                                   ↓                      │
 │  浏览器 ←── 下载加固产物 ←── ZIP 打包输出                  │
 └──────────────────────────────────────────────────────────┘
```

## 安全特性

### 加密

- AES-128-CBC + PKCS7，每次加密随机 IV
- Native 层自实现 AES（零外部依赖），不暴露标准加密库符号
- 解密后立即 `memset` 清零明文缓冲区和轮密钥

### 反调试（五重防护）

| 防护层 | 机制 |
|---|---|
| ptrace 占位 | `PTRACE_TRACEME` 抢占调试槽，阻止 GDB/LLDB |
| TracerPid 轮询 | 独立线程每 800ms 扫描 `/proc/self/status` |
| Frida 端口探测 | 尝试连接 `127.0.0.1:27042`（Frida 默认端口） |
| Frida 内存扫描 | 独立线程每 1.5s 扫描 `/proc/self/maps` 匹配 frida-agent/gadget |
| 模拟器检测 | 18 个特征文件 + `/proc/cpuinfo` hypervisor 标记 |

### 其他安全设计

- **静默崩溃**: 检测到威胁时通过空函数指针触发 SIGSEGV，伪装为随机原生崩溃
- **零日志**: 运行时壳程序无任何 Log 输出，不泄露保护逻辑
- **符号隐藏**: JNI 动态注册 + `-fvisibility=hidden`，仅导出 `JNI_OnLoad`
- **Android 14+**: InMemoryDexClassLoader 纯内存加载 + 磁盘文件 `setReadOnly()`

## 快速开始

### 1. 编译加壳工具

```bash
cd Protector-Tool && bash build.sh
```

### 2. 命令行加壳

```bash
java -cp Protector-Tool/build com.shell.protector.Main original.apk output/
```

### 3. 启动 Web 管理系统

```bash
cd Shell-Web-Server
pip install -r requirements.txt
python main.py
```

浏览器访问 `http://localhost:port`，拖拽 APK 即可一键加固。

### 4. 配置 APK 签名（可选）

设置环境变量后重启后端，加固完成后自动签名：

```bash
export KEYSTORE_PATH=/path/to/your.keystore
export KEYSTORE_PASS=your_password
export KEY_ALIAS=your_alias
```

## Web API 参考

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/upload` | 上传 APK，返回 `task_id` |
| GET | `/api/status/{task_id}` | 查询加固进度（pending/processing/completed/failed） |
| GET | `/api/download/{task_id}` | 下载加固产物 ZIP |
| GET | `/api/logs/{task_id}` | 获取加固日志 |

### 状态响应示例

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

## 构建要求

| 组件 | 版本 |
|---|---|
| JDK | 17+ |
| Python | 3.9+ |
| Android NDK | r21+（编译 Stub-App） |
| CMake | 3.18.1+ |

## 免责声明

本项目仅供安全研究和学习用途。请勿用于任何违反法律法规的行为。
