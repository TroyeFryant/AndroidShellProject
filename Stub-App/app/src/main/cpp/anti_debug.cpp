#include "anti_debug.h"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <link.h>
#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ═══════════════════════════════════════════════════════════════
//  0. 静默崩溃 —— 空函数指针触发 SIGSEGV
// ═══════════════════════════════════════════════════════════════

typedef void (*fn_void)();

__attribute__((noinline, optnone))
static void silent_crash() {
    volatile fn_void fn = nullptr;
    fn();
}

// ═══════════════════════════════════════════════════════════════
//  1. TracerPid 后台轮询
// ═══════════════════════════════════════════════════════════════

static int read_tracer_pid() {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return 0;
    char line[256];
    int tracer = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer = atoi(line + 10);
            break;
        }
    }
    fclose(fp);
    return tracer;
}

static void *tracer_pid_watcher(void *) {
    while (true) {
        if (read_tracer_pid() > 0) silent_crash();
        usleep(800 * 1000);
    }
    return nullptr;
}

void check_tracer_pid() {
    pthread_t tid;
    pthread_create(&tid, nullptr, tracer_pid_watcher, nullptr);
    pthread_detach(tid);
}

// ═══════════════════════════════════════════════════════════════
//  2. ptrace 自占位（MIUI 兼容双重验证）
// ═══════════════════════════════════════════════════════════════

void ptrace_check() {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
        if (read_tracer_pid() > 0) silent_crash();
    }
}

// ═══════════════════════════════════════════════════════════════
//  3. 双进程 ptrace 交叉守护
// ═══════════════════════════════════════════════════════════════

static void child_guard(pid_t parent_pid) {
    if (ptrace(PTRACE_ATTACH, parent_pid, nullptr, nullptr) == -1) {
        _exit(0);
    }
    waitpid(parent_pid, nullptr, 0);
    ptrace(PTRACE_CONT, parent_pid, nullptr, nullptr);

    while (true) {
        usleep(1000 * 1000);
        if (kill(parent_pid, 0) == -1) {
            _exit(0);
        }
        if (read_tracer_pid() > 0) {
            kill(parent_pid, SIGKILL);
            _exit(0);
        }
    }
}

void start_dual_process_guard() {
    pid_t parent = getpid();
    pid_t child = fork();
    if (child == 0) {
        child_guard(parent);
        _exit(0);
    } else if (child > 0) {
        usleep(100 * 1000);
    }
}

// ═══════════════════════════════════════════════════════════════
//  4. 模拟器检测
// ═══════════════════════════════════════════════════════════════

static const char *const EMULATOR_FILES[] = {
    "/system/bin/nox",
    "/system/bin/nox-prop",
    "/system/bin/noxd",
    "/system/bin/nemuvm-prop",
    "/system/bin/nemu-service",
    "/system/bin/microvirtd",
    "/system/bin/ldmountsf",
    "/system/bin/ttVM-prop",
    "/system/lib/libdroid4x.so",
    "/system/bin/androVM-prop",
    "/dev/vboxguest",
    "/dev/qemu_pipe",
    "/dev/goldfish_pipe",
    "/system/lib/libc_malloc_debug_qemu.so",
    "/system/bin/qemu-props",
    "/dev/socket/qemud",
    "/sys/qemu_trace",
    "/system/bin/ldinit",
    nullptr
};

int detect_emulator() {
    struct stat st{};
    for (int i = 0; EMULATOR_FILES[i] != nullptr; ++i) {
        if (stat(EMULATOR_FILES[i], &st) == 0) return 1;
    }

    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "hypervisor") || strstr(line, "Goldfish")) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  5. Frida 检测（八维全特征检测）
// ═══════════════════════════════════════════════════════════════

// 5a. 默认端口 + D-Bus 协议探测
static int detect_frida_port() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    struct timeval tv{};
    tv.tv_sec = 1;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(27042);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int ret = connect(sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
    if (ret == 0) {
        const char auth[] = "\x00AUTH\r\n";
        send(sock, auth, sizeof(auth) - 1, 0);
        char buf[128] = {};
        recv(sock, buf, sizeof(buf) - 1, 0);
        close(sock);
        if (strstr(buf, "REJECTED") || strstr(buf, "OK")) return 1;
        return 1;
    }
    close(sock);
    return 0;
}

// 5b. 多端口扫描（Frida 可自定义监听端口）
static int detect_frida_multi_port() {
    static const int SUSPECT_PORTS[] = {27042, 27043, 4444, 1234, 9999, 0};
    for (int i = 0; SUSPECT_PORTS[i] != 0; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct timeval tv{};
        tv.tv_usec = 200000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(SUSPECT_PORTS[i]);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (connect(sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == 0) {
            const char auth[] = "\x00AUTH\r\n";
            send(sock, auth, sizeof(auth) - 1, 0);
            char buf[128] = {};
            recv(sock, buf, sizeof(buf) - 1, 0);
            close(sock);
            if (strstr(buf, "REJECTED") || strstr(buf, "OK")) return 1;
        } else {
            close(sock);
        }
    }
    return 0;
}

// 5c. maps 内存映射关键字检测（含 memfd 无文件注入 + .rodata 特征字符串）
static int detect_frida_maps() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "frida-agent") ||
            strstr(line, "frida-gadget") ||
            strstr(line, "frida-server") ||
            strstr(line, "gum-js-loop") ||
            strstr(line, "linjector") ||
            strstr(line, "frida:rpc") ||
            strstr(line, "FridaScriptEngine") ||
            strstr(line, "GDBusProxy") ||
            strstr(line, "GumScript") ||
            strstr(line, "GLib-GIO")) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

// 5d. memfd 匿名内存映射检测（Frida memfd_create 无文件注入）
static int detect_frida_memfd() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "/memfd:")) {
            char *name_start = strstr(line, "/memfd:");
            if (name_start) {
                if (strstr(name_start, "frida") || strstr(name_start, "agent") ||
                    strstr(name_start, "gadget") || strstr(name_start, "gum")) {
                    fclose(fp);
                    return 1;
                }
                if (strstr(name_start, "(deleted)") &&
                    strstr(name_start, ".so")) {
                    fclose(fp);
                    return 1;
                }
            }
        }
    }
    fclose(fp);
    return 0;
}

// 5e. 线程名特征检测（含 gdbus）
static int detect_frida_threads() {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", getpid());
    DIR *dir = opendir(path);
    if (!dir) return 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        char comm_path[128];
        snprintf(comm_path, sizeof(comm_path), "%s/%s/comm", path, entry->d_name);
        FILE *fp = fopen(comm_path, "r");
        if (fp) {
            char name[64] = {};
            fgets(name, sizeof(name), fp);
            fclose(fp);
            if (strstr(name, "gmain") || strstr(name, "gum-js-loop") ||
                strstr(name, "gdbus") || strstr(name, "frida") ||
                strstr(name, "linjector")) {
                closedir(dir);
                return 1;
            }
        }
    }
    closedir(dir);
    return 0;
}

// 5f. Unix 抽象套接字检测（/proc/net/unix 中的 frida- 前缀）
static int detect_frida_unix_socket() {
    FILE *fp = fopen("/proc/net/unix", "r");
    if (!fp) return 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "@/frida") || strstr(line, "frida-")) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

// 5g. 进程 cmdline 扫描（遍历可见进程查找 frida-server）
static int detect_frida_process() {
    DIR *proc = opendir("/proc");
    if (!proc) return 0;

    struct dirent *entry;
    while ((entry = readdir(proc)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;
        char *end;
        long pid = strtol(entry->d_name, &end, 10);
        if (*end != '\0' || pid <= 0) continue;

        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%ld/cmdline", pid);
        FILE *fp = fopen(cmdline_path, "r");
        if (fp) {
            char buf[256] = {};
            size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
            fclose(fp);
            for (size_t i = 0; i < n; i++) {
                if (buf[i] == '\0') buf[i] = ' ';
            }
            if (strstr(buf, "frida") || strstr(buf, "frida-server") ||
                strstr(buf, "frida-inject") || strstr(buf, "frida-portal")) {
                closedir(proc);
                return 1;
            }
        }
    }
    closedir(proc);
    return 0;
}

// 5h. /proc/self/fd 符号链接扫描（Frida 会在 fd 中留下 memfd/socket 特征）
static int detect_frida_fd() {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return 0;

    char path[64], link[256];
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        ssize_t len = readlink(path, link, sizeof(link) - 1);
        if (len > 0) {
            link[len] = '\0';
            if (strstr(link, "frida") || strstr(link, "linjector") ||
                (strstr(link, "memfd:") && strstr(link, "(deleted)"))) {
                closedir(dir);
                return 1;
            }
        }
    }
    closedir(dir);
    return 0;
}

int detect_frida() {
    return detect_frida_port() || detect_frida_multi_port() ||
           detect_frida_maps() || detect_frida_memfd() ||
           detect_frida_threads() || detect_frida_unix_socket() ||
           detect_frida_process() || detect_frida_fd();
}

static void *frida_watcher(void *) {
    while (true) {
        if (detect_frida()) silent_crash();
        usleep(1500 * 1000);
    }
    return nullptr;
}

// ═══════════════════════════════════════════════════════════════
//  6. 时间差检测（反单步调试）
// ═══════════════════════════════════════════════════════════════

static struct timespec timing_start;
static const long TIMING_THRESHOLD_MS = 800;

void timing_check_begin() {
    clock_gettime(CLOCK_MONOTONIC, &timing_start);
}

void timing_check_end() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed_ms = (now.tv_sec - timing_start.tv_sec) * 1000 +
                      (now.tv_nsec - timing_start.tv_nsec) / 1000000;
    if (elapsed_ms > TIMING_THRESHOLD_MS) {
        silent_crash();
    }
}

// ═══════════════════════════════════════════════════════════════
//  7. GOT/PLT Hook 检测
// ═══════════════════════════════════════════════════════════════

struct MapRange {
    uintptr_t start;
    uintptr_t end;
};

static int find_map_range(const char *lib_name, MapRange *range) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    range->start = UINTPTR_MAX;
    range->end   = 0;
    int found = 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name) && strstr(line, "r-xp")) {
            uintptr_t s, e;
            if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &s, &e) == 2) {
                if (s < range->start) range->start = s;
                if (e > range->end) range->end = e;
                found = 1;
            }
        }
    }
    fclose(fp);
    return found;
}

int detect_hook() {
    MapRange libc_range = {};
    if (!find_map_range("libc.so", &libc_range)) return 0;

    void *handle = dlopen("libc.so", RTLD_NOW);
    if (!handle) return 0;

    const char *funcs[] = {"fopen", "ptrace", "open", "read", "mmap", nullptr};

    for (int i = 0; funcs[i]; i++) {
        void *addr = dlsym(handle, funcs[i]);
        if (addr) {
            auto a = reinterpret_cast<uintptr_t>(addr);
            if (a < libc_range.start || a >= libc_range.end) {
                dlclose(handle);
                return 1;
            }
        }
    }
    dlclose(handle);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  8. Root / Magisk / Xposed / LSPosed 检测
// ═══════════════════════════════════════════════════════════════

static const char *const ROOT_FILES[] = {
    "/system/xbin/su",
    "/system/bin/su",
    "/sbin/su",
    "/su/bin/su",
    "/data/local/su",
    "/data/local/xbin/su",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/sbin/.magisk",
    "/data/adb/magisk",
    "/data/adb/modules",
    "/system/framework/XposedBridge.jar",
    "/data/adb/lspd",
    "/data/adb/modules/zygisk_lsposed",
    "/data/adb/modules/riru_lsposed",
    "/data/adb/modules/riru-core",
    "/data/adb/modules/zygisk_shamiko",
    "/data/adb/modules/edxposed",
    "/data/adb/modules/riru_edxposed",
    "/system/bin/app_process_xposed",
    "/system/lib/libxposed_art.so",
    "/system/lib64/libxposed_art.so",
    "/system/lib/libsubstrate.so",
    "/system/lib64/libsubstrate.so",
    "/system/xposed.prop",
    "/data/local/tmp/frida-server",
    "/data/local/tmp/frida",
    "/data/local/tmp/re.frida.server",
    "/data/local/tmp/libfrida-gadget.so",
    "/system/bin/frida-server",
    "/system/xbin/frida-server",
    nullptr
};

static int detect_root_files() {
    struct stat st{};
    for (int i = 0; ROOT_FILES[i]; i++) {
        if (stat(ROOT_FILES[i], &st) == 0) return 1;
    }
    return 0;
}

static int detect_xposed_maps() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "XposedBridge") ||
            strstr(line, "libxposed") ||
            strstr(line, "lspd") ||
            strstr(line, "edxposed") ||
            strstr(line, "riru") ||
            strstr(line, "zygisk") ||
            strstr(line, "shamiko") ||
            strstr(line, "substrate") ||
            strstr(line, "sandhook") ||
            strstr(line, "yahfa") ||
            strstr(line, "epic") ||
            strstr(line, "whale") ||
            strstr(line, "lsplant") ||
            strstr(line, "pine")) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

int detect_root_environment() {
    return detect_root_files() || detect_xposed_maps();
}

// ═══════════════════════════════════════════════════════════════
//  9. 代码段完整性校验（.text CRC32）
// ═══════════════════════════════════════════════════════════════

static uint32_t crc32_compute(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

static volatile uint32_t g_text_crc_expected = 0;

static int get_so_text_section(const char *so_name,
                               uintptr_t *text_addr, size_t *text_size) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    uintptr_t base = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, so_name) && strstr(line, "r-xp")) {
            sscanf(line, "%" SCNxPTR, &base);
            break;
        }
    }
    fclose(fp);
    if (!base) return 0;

    auto *ehdr = reinterpret_cast<ElfW(Ehdr) *>(base);
    auto *shdr = reinterpret_cast<ElfW(Shdr) *>(base + ehdr->e_shoff);

    const char *shstrtab = nullptr;
    if (ehdr->e_shstrndx != SHN_UNDEF) {
        shstrtab = reinterpret_cast<const char *>(base + shdr[ehdr->e_shstrndx].sh_offset);
    }
    if (!shstrtab) {
        *text_addr = base;
        *text_size = 4096;
        return 1;
    }

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (strcmp(shstrtab + shdr[i].sh_name, ".text") == 0) {
            *text_addr = base + shdr[i].sh_offset;
            *text_size = shdr[i].sh_size;
            return 1;
        }
    }
    *text_addr = base;
    *text_size = 4096;
    return 1;
}

int verify_code_integrity() {
    uintptr_t text_addr = 0;
    size_t text_size = 0;
    if (!get_so_text_section("libguard.so", &text_addr, &text_size)) return 0;

    uint32_t current = crc32_compute(reinterpret_cast<const uint8_t *>(text_addr), text_size);

    if (g_text_crc_expected == 0) {
        g_text_crc_expected = current;
        return 0;
    }

    return (current != g_text_crc_expected) ? 1 : 0;
}

static void *integrity_watcher(void *) {
    usleep(2000 * 1000);
    while (true) {
        if (verify_code_integrity()) silent_crash();
        usleep(3000 * 1000);
    }
    return nullptr;
}

// ═══════════════════════════════════════════════════════════════
//  10. 容器/沙箱环境检测
// ═══════════════════════════════════════════════════════════════

static int count_proc_dirs() {
    DIR *dir = opendir("/proc");
    if (!dir) return -1;
    int cnt = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_DIR) {
            char *end;
            strtol(entry->d_name, &end, 10);
            if (*end == '\0') cnt++;
        }
    }
    closedir(dir);
    return cnt;
}

static int detect_sandbox_fd() {
    char path[128], link[256];
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        ssize_t len = readlink(path, link, sizeof(link) - 1);
        if (len > 0) {
            link[len] = '\0';
            if (strstr(link, "virtual-app") || strstr(link, "sandbox") ||
                strstr(link, "parallel") || strstr(link, "dual") ||
                strstr(link, "VirtualXposed") || strstr(link, "io.va.exposed")) {
                closedir(dir);
                return 1;
            }
        }
    }
    closedir(dir);
    return 0;
}

static const char *const SANDBOX_FILES[] = {
    "/data/data/com.lbe.parallel.intl",
    "/data/data/com.excelliance.dualaid",
    "/data/data/com.polestar.multiaccount",
    "/data/data/io.virtualapp",
    "/data/data/com.ludashi.dualspace",
    "/data/user/999",
    nullptr,
};

int detect_sandbox() {
    int proc_cnt = count_proc_dirs();
    if (proc_cnt > 0 && proc_cnt < 50) return 1;

    if (detect_sandbox_fd()) return 1;

    struct stat st{};
    for (int i = 0; SANDBOX_FILES[i]; i++) {
        if (stat(SANDBOX_FILES[i], &st) == 0) return 1;
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  11. 云手机环境检测
// ═══════════════════════════════════════════════════════════════

static int get_thermal_zone_count() {
    DIR *dir = opendir("/sys/class/thermal/");
    if (!dir) return -1;
    int cnt = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strstr(entry->d_name, "thermal_zone")) cnt++;
    }
    closedir(dir);
    return cnt;
}

static const char *const CLOUD_PHONE_FILES[] = {
    "/system/bin/cloud_phone",
    "/system/lib/libcloud_phone.so",
    "/system/etc/cloud_phone.prop",
    "/system/bin/redfinger",
    "/system/lib/libbaiducloud.so",
    "/vendor/etc/nbd_phone.prop",
    nullptr,
};

int detect_cloud_phone() {
    if (get_thermal_zone_count() == 0) return 1;

    struct stat st{};
    for (int i = 0; CLOUD_PHONE_FILES[i]; i++) {
        if (stat(CLOUD_PHONE_FILES[i], &st) == 0) return 1;
    }

    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[512];
        int has_hardware = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Hardware", 8) == 0) {
                has_hardware = 1;
                if (strstr(line, "placeholder") || strstr(line, "virtual") || strstr(line, "Cloud")) {
                    fclose(fp);
                    return 1;
                }
            }
        }
        fclose(fp);
        if (!has_hardware) return 1;
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  12. Mount 异常分析
// ═══════════════════════════════════════════════════════════════

int detect_mount_anomaly() {
    FILE *fp = fopen("/proc/mounts", "r");
    if (!fp) return 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "magisk") ||
            (strstr(line, "tmpfs") && (strstr(line, "/system") || strstr(line, "/vendor"))) ||
            strstr(line, "/data/adb/modules")) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);

    fp = fopen("/proc/self/mountinfo", "r");
    if (!fp) return 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "magisk") || strstr(line, "core/mirror")) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  13. ART 方法完整性检测（JNI 入口点地址验证）
// ═══════════════════════════════════════════════════════════════

static int check_art_method_in_range(void *method_entry, const char *expected_lib) {
    if (!method_entry) return 0;
    auto addr = reinterpret_cast<uintptr_t>(method_entry);
    MapRange range = {};
    if (!find_map_range(expected_lib, &range)) return 0;
    return (addr < range.start || addr >= range.end) ? 1 : 0;
}

int detect_art_hook() {
    MapRange oat_range = {};
    int found = find_map_range("boot.oat", &oat_range) || find_map_range("boot-framework.oat", &oat_range);
    if (!found) return 0;

    MapRange art_range = {};
    if (!find_map_range("libart.so", &art_range)) return 0;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    int suspicious = 0;
    while (fgets(line, sizeof(line), fp)) {
        if ((strstr(line, "frida") || strstr(line, "substrate") ||
             strstr(line, "whale") || strstr(line, "sandhook") ||
             strstr(line, "lsplant") || strstr(line, "pine")) &&
            strstr(line, "r-xp")) {
            suspicious++;
        }
    }
    fclose(fp);
    return (suspicious > 0) ? 1 : 0;
}

// ═══════════════════════════════════════════════════════════════
//  14. dlsym 导出符号探测（EnvScope 整合）
// ═══════════════════════════════════════════════════════════════

int detect_exported_symbols() {
    static const char *const SUSPECT_SYMBOLS[] = {
        "frida_agent_main",
        "frida_gadget_main",
        "gum_init_embedded",
        "gum_deinit_embedded",
        "gum_interceptor_attach",
        "gum_script_backend_obtain_qjs",
        "gum_script_backend_obtain_v8",
        "xposedCallHandler",
        "MSHookFunction",
        "MSHookMessageEx",
        "Java_de_robv_android_xposed_XposedBridge_hookMethodNative",
        nullptr,
    };

    for (int i = 0; SUSPECT_SYMBOLS[i]; i++) {
        if (dlsym(RTLD_DEFAULT, SUSPECT_SYMBOLS[i]) != nullptr) {
            return 1;
        }
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  15. 异常 RWX 可执行内存段检测（EnvScope + RiskEngine 整合）
// ═══════════════════════════════════════════════════════════════

int detect_rwx_memory() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    int suspicious_count = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, "rwxp")) continue;
        if (strstr(line, "/system/") || strstr(line, "/apex/") ||
            strstr(line, "[anon:dalvik") || strstr(line, "jit-cache") ||
            strstr(line, "dalvik-jit") || strstr(line, "boot-framework") ||
            strstr(line, "[vectors]") || strstr(line, "scudo") ||
            strstr(line, "linker_alloc")) continue;
        suspicious_count++;
    }
    fclose(fp);
    return (suspicious_count > 0) ? 1 : 0;
}

// ═══════════════════════════════════════════════════════════════
//  16. dl_iterate_phdr 加载库扫描（EnvScope 整合）
// ═══════════════════════════════════════════════════════════════

static const char *const DL_SUSPECT_TOKENS[] = {
    "frida", "gadget", "xposed", "lsposed", "edxposed",
    "riru", "zygisk", "substrate", "sandhook",
    "yahfa", "epic", "whale", "linjector", nullptr,
};

static int dl_iterate_callback(struct dl_phdr_info *info, size_t, void *data) {
    if (!info || !info->dlpi_name || info->dlpi_name[0] == '\0') return 0;
    int *found = static_cast<int *>(data);
    for (int i = 0; DL_SUSPECT_TOKENS[i]; i++) {
        if (strstr(info->dlpi_name, DL_SUSPECT_TOKENS[i])) {
            *found = 1;
            return 1;
        }
    }
    return 0;
}

int detect_loaded_libraries() {
    int found = 0;
    dl_iterate_phdr(dl_iterate_callback, &found);
    return found;
}

// ═══════════════════════════════════════════════════════════════
//  17. /proc/net/tcp 端口表扫描（EnvScope 整合）
// ═══════════════════════════════════════════════════════════════

int detect_tcp_port_table() {
    static const char *HEX_PORTS[] = {
        ":69B8", ":69B9", ":69BA", ":69BB", ":69BC",
        ":69BD", ":69BE", ":69BF", ":69C0", ":69C1", ":69C2",
        ":5D8A",
        nullptr,
    };

    const char *paths[] = {"/proc/net/tcp", "/proc/net/tcp6", nullptr};
    for (int p = 0; paths[p]; p++) {
        FILE *fp = fopen(paths[p], "r");
        if (!fp) continue;
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            for (int h = 0; HEX_PORTS[h]; h++) {
                if (strstr(line, HEX_PORTS[h])) {
                    fclose(fp);
                    return 1;
                }
            }
        }
        fclose(fp);
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
//  18. SIGTRAP 信号探针（RiskEngine 整合）
// ═══════════════════════════════════════════════════════════════

#include <signal.h>
#include <sys/syscall.h>

static volatile sig_atomic_t g_sigtrap_fired = 0;

static void sigtrap_handler(int, siginfo_t *, void *) {
    g_sigtrap_fired = 1;
}

int detect_sigtrap_intercept() {
    struct sigaction action{}, old_action{};
    action.sa_sigaction = sigtrap_handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);

    if (sigaction(SIGTRAP, &action, &old_action) != 0) return 0;

    g_sigtrap_fired = 0;
    pid_t pid = getpid();
    pid_t tid = static_cast<pid_t>(syscall(__NR_gettid));
    syscall(__NR_tgkill, pid, tid, SIGTRAP);
    sigaction(SIGTRAP, &old_action, nullptr);

    return g_sigtrap_fired ? 0 : 1;
}

// ═══════════════════════════════════════════════════════════════
//  统一入口
// ═══════════════════════════════════════════════════════════════

void start_anti_debug() {
    // Layer 1: ptrace 自占位 + TracerPid 验证
    ptrace_check();

    // Layer 2: TracerPid 后台轮询线程
    check_tracer_pid();

    // Layer 3: 双进程 ptrace 交叉守护
    start_dual_process_guard();

    // Layer 4: 模拟器检测
    if (detect_emulator()) silent_crash();

    // Layer 5: Frida 即时检测
    if (detect_frida()) silent_crash();

    // Layer 6: Frida 持续监控线程
    pthread_t ftid;
    pthread_create(&ftid, nullptr, frida_watcher, nullptr);
    pthread_detach(ftid);

    // Layer 7: GOT/PLT Hook 检测
    if (detect_hook()) silent_crash();

    // Layer 8: Root/Magisk/Xposed 环境检测
    if (detect_root_environment()) silent_crash();

    // Layer 9: 代码段完整性初始化 + 后台校验
    verify_code_integrity();
    pthread_t itid;
    pthread_create(&itid, nullptr, integrity_watcher, nullptr);
    pthread_detach(itid);

    // Layer 10: 时间差检测（标记起始点）
    timing_check_begin();

    // Layer 11: 容器/沙箱环境检测（RiskEngine 整合）
    if (detect_sandbox()) silent_crash();

    // Layer 12: 云手机环境检测（RiskEngine 整合）
    if (detect_cloud_phone()) silent_crash();

    // Layer 13: Mount 异常分析（RiskEngine 整合）
    if (detect_mount_anomaly()) silent_crash();

    // Layer 14: ART 方法完整性检测（RiskEngine 整合）
    if (detect_art_hook()) silent_crash();

    // Layer 15: dlsym 导出符号探测（EnvScope 整合）
    if (detect_exported_symbols()) silent_crash();

    // Layer 16: 异常 RWX 可执行内存段检测（EnvScope + RiskEngine 整合）
    if (detect_rwx_memory()) silent_crash();

    // Layer 17: dl_iterate_phdr 加载库扫描（EnvScope 整合）
    if (detect_loaded_libraries()) silent_crash();

    // Layer 18: /proc/net/tcp 端口表扫描（EnvScope 整合）
    if (detect_tcp_port_table()) silent_crash();

    // Layer 19: SIGTRAP 信号探针（RiskEngine 整合）
    if (detect_sigtrap_intercept()) silent_crash();
}
