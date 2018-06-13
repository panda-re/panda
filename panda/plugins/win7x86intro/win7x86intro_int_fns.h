#ifndef __WIN7X86INTRO_INT_FNS_H__
#define __WIN7X86INTRO_INT_FNS_H__

PTR get_win7_kpcr(CPUState *cpu);
HandleObject *get_win7_handle_object(CPUState *cpu, uint32_t eproc, uint32_t handle);

#endif
