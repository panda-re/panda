#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls_common.h"

extern "C" {
#include "gen_syscalls_ext_typedefs.h"
#include "gen_syscall_ppp_extern_return.h"
}

void syscall_return_switch_{{os}}_{{arch}}(CPUState *cpu, target_ulong pc, target_ulong ordinal, ReturnPoint &rp) {
#ifdef {{arch_conf.qemu_target}}
	switch(ordinal) {
		{%- for syscall in syscalls %}
		// {{syscall.no}} {{syscall.rettype}} {{syscall.name}} {{syscall.args_raw}}
		case {{syscall.no}}: {
			{%- for arg in syscall.args %}
			{{arg.temp_decl_code}}
			{%- endfor %}
			if (PPP_CHECK_CB(on_{{syscall.name}}_return)) {
				{%- for arg in syscall.args %}
				{{arg.memcpy_rp2temp_code}}
				{%- endfor %}
			}
			PPP_RUN_CB(on_{{syscall.name}}_return, {{syscall.cargs}}) ;
		}; break;
		{%- endfor %}
		default:
			PPP_RUN_CB(on_unknown_sys_return, cpu, pc, rp.ordinal);
	}
	PPP_RUN_CB(on_all_sys_return, cpu, pc, rp.ordinal);
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
