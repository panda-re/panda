#pragma once

char *get_handle_name(CPUState *cpu, uint64_t handle);

char *get_cwd(CPUState *cpu);

int64_t get_file_handle_pos(CPUState *cpu, uint64_t handle);

void *get_windows_process_manager(void);
