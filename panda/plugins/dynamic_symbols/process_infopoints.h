bool asid_changed(CPUState *env, target_ulong old_asid, target_ulong new_asid);
void sys_mmap_return(
    CPUState* cpu,
    target_ulong pc,
    target_ulong arg0,
    target_ulong arg1,
    target_ulong arg2,
    target_ulong arg3,
    target_ulong arg4,
    target_ulong arg5);
void sys_old_mmap_return(CPUState *cpu, target_ulong pc, uint32_t arg0);
void sys_mmap2_return(CPUState* cpu, target_ulong pc, unsigned int b, unsigned int c, int d, int e, int f, unsigned int g);
void sys_mmap_arm64_return(CPUState* cpu, target_ulong pc, long unsigned int b, unsigned int c, int d, int e, int f, long unsigned int g);
void sys_mmap2_mips_return(CPUState* cpu, target_ulong pc, unsigned int b, unsigned int c, int d, int e, int f, unsigned int g);
void sys_mmap_mips_return(CPUState* cpu, target_ulong pc, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e, unsigned int f);
void sys_exit_enter(CPUState *cpu, target_ulong pc, int exit_code);
void recv_auxv(CPUState *env, TranslationBlock *tb, struct auxv_values *av);