#include "anti_debug.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ═══════════════════════════════════════════════════════════════
//  静默崩溃 —— 通过空函数指针触发 SIGSEGV，伪装为非预期崩溃
// ═══════════════════════════════════════════════════════════════

typedef void (*fn_void)();

__attribute__((noinline, optnone))
static void silent_crash() {
    volatile fn_void fn = nullptr;
    fn();
}

// ═══════════════════════════════════════════════════════════════
//  1. TracerPid 轮询
// ═══════════════════════════════════════════════════════════════

static void *tracer_pid_watcher(void * /* unused */) {
    while (true) {
        FILE *fp = fopen("/proc/self/status", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    int tracer = atoi(line + 10);
                    if (tracer > 0) {
                        fclose(fp);
                        silent_crash();
                    }
                    break;
                }
            }
            fclose(fp);
        }
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
//  2. ptrace 自占位
//  注意：MIUI 等 ROM 的 SELinux 策略可能直接禁止 ptrace，
//  此时 errno == EPERM 并不意味着正在被调试，需要结合 TracerPid 判断。
// ═══════════════════════════════════════════════════════════════

void ptrace_check() {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
        // ptrace 失败，检查是否真的有调试器 attach
        FILE *fp = fopen("/proc/self/status", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    int tracer = atoi(line + 10);
                    fclose(fp);
                    if (tracer > 0) {
                        silent_crash();
                    }
                    return; // ptrace 被系统策略拒绝，非调试场景
                }
            }
            fclose(fp);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  3. 模拟器检测
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
    nullptr
};

int detect_emulator() {
    struct stat st{};
    for (int i = 0; EMULATOR_FILES[i] != nullptr; ++i) {
        if (stat(EMULATOR_FILES[i], &st) == 0) {
            return 1;
        }
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
//  4. Frida 检测
// ═══════════════════════════════════════════════════════════════

// 4a. 探测 Frida 默认监听端口 27042
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
    close(sock);
    return ret == 0 ? 1 : 0;
}

// 4b. 扫描 /proc/self/maps 中的 frida-agent
static int detect_frida_maps() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "frida-agent") ||
            strstr(line, "frida-gadget") ||
            strstr(line, "frida-server")) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

int detect_frida() {
    return detect_frida_port() || detect_frida_maps();
}

// Frida 持续检测线程
static void *frida_watcher(void * /* unused */) {
    while (true) {
        if (detect_frida()) {
            silent_crash();
        }
        usleep(1500 * 1000);
    }
    return nullptr;
}

// ═══════════════════════════════════════════════════════════════
//  统一入口
// ═══════════════════════════════════════════════════════════════

void start_anti_debug() {
    ptrace_check();
    check_tracer_pid();

    if (detect_emulator()) {
        silent_crash();
    }

    if (detect_frida()) {
        silent_crash();
    }

    pthread_t ftid;
    pthread_create(&ftid, nullptr, frida_watcher, nullptr);
    pthread_detach(ftid);
}
