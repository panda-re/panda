#ifndef __WIN2000X86INTRO_INT_FNS_H__
#define __WIN2000X86INTRO_INT_FNS_H__

PTR get_win2000_kpcr(CPUState *cpu);
HandleObject *get_win2000_handle_object(CPUState *cpu, uint32_t eproc, uint32_t handle);
#ifndef CONFIG_DARWIN
PTR get_win2000_kddebugger_data(CPUState *cpu);
#endif

#endif
