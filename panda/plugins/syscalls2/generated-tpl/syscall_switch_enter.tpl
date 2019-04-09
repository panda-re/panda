#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include <iostream>
#include "syscalls2.h"
#include "syscalls2_info.h"

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
void syscall_enter_switch_{{os}}_{{arch}}(CPUState *cpu, target_ptr_t pc) {
#if {{arch_conf.qemu_target}}
	CPUArchState *env = (CPUArchState*)cpu->env_ptr;
	syscall_ctx_t ctx = {0};
	ctx.no = {{arch_conf.rt_callno_reg}};
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
		auto idx = std::make_pair(ctx.retaddr, ctx.asid);
		/*
		auto ctx_old_it = running_syscalls.find(idx);
		if (ctx_old_it != running_syscalls.end()) {
			auto ctx_old = ctx_old_it->second;
			const syscall_info_t *call_old = &syscall_info[ctx_old.no];
			//std::cerr << "%%% " << call_old->name << std::endl;
			//std::cerr << "%%% " << call->name << std::endl;
			//std::cerr << std::endl;
			//assert(false && "duplicate insertion");
		}
		*/
		running_syscalls.insert(std::make_pair(idx, ctx));
		//running_syscalls[std::make_pair(ctx.retaddr, ctx.asid)] = ctx;
	}
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
