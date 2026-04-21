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
void start_dual_process_guard();
void timing_check_begin();
void timing_check_end();
int  detect_hook();
int  detect_root_environment();
int  verify_code_integrity();

#ifdef __cplusplus
}
#endif

#endif // SHELL_ANTI_DEBUG_H
