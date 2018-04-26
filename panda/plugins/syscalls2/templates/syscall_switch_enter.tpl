#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls_common.h"

extern "C" {
#include "gen_syscalls_ext_typedefs.h"
#include "gen_syscall_ppp_extern_enter.h"
#include "gen_syscall_ppp_extern_return.h"
}

void syscall_enter_switch_{{os}}_{{arch}}(CPUState *cpu, target_ulong pc) {
#ifdef {{arch_conf.qemu_target}}
	CPUArchState *env = (CPUArchState*)cpu->env_ptr;
	ReturnPoint rp;
	rp.ordinal = {{arch_conf.rt_callno_reg}};
	rp.proc_id = panda_current_asid(cpu);
	rp.retaddr = calc_retaddr(cpu, pc);
	switch({{arch_conf.rt_callno_reg}}) {
		{%- for syscall in syscalls %}
		// {{syscall.no}} {{syscall.rettype}} {{syscall.name}} {{syscall.args_raw}}
		case {{syscall.no}}: {
			{%- for arg in syscall.args %}
			{{arg.temp_assg_code}}
			{%- endfor %}
			if (PPP_CHECK_CB(on_{{syscall.name}}_return)) {
				{%- for arg in syscall.args %}
				{{arg.memcpy_temp2rp_code}}
				{%- endfor %}
			}
			PPP_RUN_CB(on_{{syscall.name}}_enter, {{syscall.cargs}});
		}; break;
		{% endfor %}
		default:
			PPP_RUN_CB(on_unknown_sys_enter, cpu, pc, {{arch_conf.rt_callno_reg}});
	}
	PPP_RUN_CB(on_all_sys_enter, cpu, pc, {{arch_conf.rt_callno_reg}});
	appendReturnPoint(rp);
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
