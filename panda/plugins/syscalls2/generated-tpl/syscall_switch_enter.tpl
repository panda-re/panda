#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls2_info.h"

extern const syscall_info_t *syscall_info;
extern const syscall_meta_t *syscall_meta;

extern "C" {
#include "syscalls_ext_typedefs.h"
#include "syscall_ppp_extern_enter.h"
#include "syscall_ppp_extern_return.h"
}

void syscall_enter_switch_{{os}}_{{arch}}(CPUState *cpu, target_ptr_t pc) {
#ifdef {{arch_conf.qemu_target}}
	CPUArchState *env = (CPUArchState*)cpu->env_ptr;
	syscall_ctx_t ctx;
	ctx.no = {{arch_conf.rt_callno_reg}};
	ctx.asid = panda_current_asid(cpu);
	ctx.retaddr = calc_retaddr(cpu, pc);
	const syscall_info_t *call = (syscall_meta == NULL || ctx.no > syscall_meta->max_generic) ? NULL : &syscall_info[ctx.no];
	switch (ctx.no) {
		{%- for syscall in syscalls %}
		// {{syscall.no}} {{syscall.rettype}} {{syscall.name}} {{syscall.args_raw}}
		case {{syscall.no}}: {
			{%- for arg in syscall.args %}
			{{arg.emit_temp_assignment()}}
			{%- endfor %}
			if (PPP_CHECK_CB(on_{{syscall.name}}_return) || PPP_CHECK_CB(on_all_sys_enter2) || PPP_CHECK_CB(on_all_sys_return2)) {
				{%- for arg in syscall.args %}
				{{arg.emit_memcpy_temp_to_ref()}}
				{%- endfor %}
			}
			PPP_RUN_CB(on_{{syscall.name}}_enter, {{syscall.cargs}});
		}; break;
		{%- endfor %}
		default:
			PPP_RUN_CB(on_unknown_sys_enter, cpu, pc, ctx.no);
	}
	PPP_RUN_CB(on_all_sys_enter, cpu, pc, ctx.no);
	PPP_RUN_CB(on_all_sys_enter2, cpu, pc, call, &ctx);
	running_syscalls[std::make_pair(ctx.retaddr, ctx.asid)] = ctx;
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
