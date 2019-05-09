#ifndef __WIN7X86INTRO_INT_FNS_H__
#define __WIN7X86INTRO_INT_FNS_H__

PTR get_winxp_kpcr(CPUState *cpu);
HandleObject *get_winxp_handle_object(CPUState *cpu, uint32_t eproc, uint32_t handle);
PTR get_winxp_kdbg(CPUState *cpu);

#endif
