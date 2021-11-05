#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls2_info.h"
#include "hooks/hooks_int_fns.h"

extern const syscall_info_t *syscall_info;
extern const syscall_meta_t *syscall_meta;

extern "C" {
#include "syscalls_ext_typedefs.h"
#include "syscall_ppp_extern_enter.h"
#include "syscall_ppp_extern_return.h"
}

/**
 * @brief Called when a system call invocation is identified.
 * Invokes all registered callbacks that should run for the call.
 *
 * Additionally, stores the context of the system call (number, asid,
 * arguments, return address) to prepare for handling the respective
 * system call return callbacks.
 */
void syscall_enter_switch_{{os}}_{{arch}}(CPUState *cpu, target_ptr_t pc, int static_callno) {
#if {{arch_conf.qemu_target}}
	CPUArchState *env = (CPUArchState*)cpu->env_ptr;
	syscall_ctx_t ctx = {0};
	if (static_callno == -1) {
	  ctx.no = {{arch_conf.rt_callno_reg}};
	} else {
	  ctx.no = static_callno;
	}
	ctx.asid = panda_current_asid(cpu);
	ctx.retaddr = calc_retaddr(cpu, pc);
	bool panda_noreturn;	// true if PANDA should not track the return of this system call
	const syscall_info_t *call = (syscall_meta == NULL || ctx.no > syscall_meta->max_generic) ? NULL : &syscall_info[ctx.no];

	switch (ctx.no) {
	{%- for syscall in syscalls %}
	// {{syscall.no}} {{syscall.rettype}} {{syscall.name}} {{syscall.args_raw}}
	case {{syscall.no}}: {
		panda_noreturn = {{ 'true' if syscall.panda_noreturn else 'false' }};
		{%- if syscall.args|length > 0 %}
		{%- for arg in syscall.args %}
		{{arg.emit_temp_assignment()}}
		{%- endfor %}
		if (PPP_CHECK_CB(on_all_sys_enter2) ||
			(!panda_noreturn && (PPP_CHECK_CB(on_all_sys_return2) ||
					PPP_CHECK_CB(on_{{syscall.name}}_return)))) {
			{%- for arg in syscall.args %}
			{{arg.emit_memcpy_temp_to_ref()}}
			{%- endfor %}
		}
		{%- endif %}
		PPP_RUN_CB(on_{{syscall.name}}_enter, {{syscall.cargs}});
	}; break;
	{%- endfor %}
	default:
		panda_noreturn = false;
		PPP_RUN_CB(on_unknown_sys_enter, cpu, pc, ctx.no);
	} // switch (ctx.no)

	PPP_RUN_CB(on_all_sys_enter, cpu, pc, ctx.no);
	PPP_RUN_CB(on_all_sys_enter2, cpu, pc, call, &ctx);
	if (!panda_noreturn) {
		//struct hook h;
		//h.addr = ctx.retaddr;
		//h.asid = ctx.asid;
		//h.cb.start_block_exec = hook_syscall_return;
		//h.type = PANDA_CB_START_BLOCK_EXEC;
		//h.enabled = true;
		//h.km = MODE_ANY; //you'd expect this to be user only
		//hooks_add_hook(&h);
		printf("SYSENTER: PC " TARGET_FMT_lx " RET: " TARGET_FMT_lx "\n", panda_current_pc(cpu), ctx.retaddr);

		running_syscalls[ctx.asid].push_back(ctx);
	}
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
