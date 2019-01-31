#include "osi_linux.h"
#include "kernel_2_4_x_profile.h"

void kernel24x_get_current_process(CPUState *cpu, OsiProc **proc)
{
	OsiProc *p = NULL;
	target_ptr_t kernel_esp = panda_current_sp(cpu);
	if (false == panda_in_kernel(cpu)) {
		kernel_esp -= 20;
	}
	target_ptr_t ts = kernel_esp & THREADINFO_MASK;
	if (ts) {
		p = (OsiProc *)g_malloc(sizeof(OsiProc));
		fill_osiproc(cpu, p, ts);
	}
	*proc = p;

}

void kernel24x_get_current_thread(CPUState *cpu, OsiThread **thr)
{
	OsiThread *t = NULL;
	target_ptr_t kernel_esp = panda_current_sp(cpu);
	if (false == panda_in_kernel(cpu)) {
		kernel_esp -= 20;
	}
	target_ptr_t ts = kernel_esp & THREADINFO_MASK;
	if (ts) {
		t = (OsiThread *)g_malloc(sizeof(OsiThread));
		fill_osithread(cpu, t, ts);
	}
	*thr= t;
}

IMPLEMENT_OFFSET_GET(get_files_fds, files_struct, target_ptr_t, ki.fs.fd_offset,
                     0)
target_ptr_t kernel24x_get_files_fds(CPUState *cpu, target_ptr_t files)
{
	return get_files_fds(cpu, files);
}

/* vim:set tabstop=4 softtabstop=4 noexpandtab: */
