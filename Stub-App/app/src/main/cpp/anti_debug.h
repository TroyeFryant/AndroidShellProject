#ifndef SHELL_ANTI_DEBUG_H
#define SHELL_ANTI_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

void start_anti_debug();
void check_tracer_pid();
void ptrace_check();
int  detect_emulator();
int  detect_frida();

#ifdef __cplusplus
}
#endif

#endif // SHELL_ANTI_DEBUG_H
