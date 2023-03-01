#pragma once
// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.
void inject_syscall(CPUState *cpu, target_ulong callno, size_t nargs, target_ulong *raw_args);
//void sys_access(CPUState *cpu, target_ulong pathname, target_ulong mode);
void sys_access(CPUState *cpu, target_ulong *raw_args);
// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
