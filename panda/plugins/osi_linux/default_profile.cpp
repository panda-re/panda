#include "osi_linux.h"
#include "default_profile.h"

void default_get_current_process(CPUState *cpu, OsiProc **proc)
{
	OsiProc *p = NULL;
	target_ptr_t kernel_esp = panda_current_sp(cpu);
	target_ptr_t ts = get_task_struct(cpu, (kernel_esp & THREADINFO_MASK));
	if (ts) {
		p = (OsiProc *)g_malloc(sizeof(OsiProc));
		fill_osiproc(cpu, p, ts);
	}
	*proc = p;

}

void default_get_current_thread(CPUState *cpu, OsiThread **thr)
{
	OsiThread *t = NULL;
	target_ptr_t kernel_esp = panda_current_sp(cpu);
	target_ptr_t ts = get_task_struct(cpu, (kernel_esp & THREADINFO_MASK));
	if (ts) {
		t = (OsiThread *)g_malloc(sizeof(OsiThread));
		fill_osithread(cpu, t, ts);
	}
	*thr= t;
}

/* vim:set tabstop=4 softtabstop=4 noexpandtab: */
