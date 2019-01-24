#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "syscalls2.h"
#include "syscalls2_info.h"

extern const syscall_info_t *syscall_info;
extern const syscall_meta_t *syscall_meta;

extern "C" {
#include "syscalls_ext_typedefs.h"
#include "syscall_ppp_extern_return.h"
}

void syscall_return_switch_{{os}}_{{arch}}(CPUState *cpu, target_ptr_t pc, const syscall_ctx_t *ctx) {
#ifdef {{arch_conf.qemu_target}}
	const syscall_info_t *call = (syscall_meta == NULL || ctx->no > syscall_meta->max_generic) ? NULL : &syscall_info[ctx->no];
	switch (ctx->no) {
		{%- for syscall in syscalls %}
		// {{syscall.no}} {{syscall.rettype}} {{syscall.name}} {{syscall.args_raw}}
		case {{syscall.no}}: {
			{%- for arg in syscall.args %}
			{{arg.emit_temp_declaration()}}
			{%- endfor %}
			if (PPP_CHECK_CB(on_{{syscall.name}}_return) || PPP_CHECK_CB(on_all_sys_return2)) {
				{%- for arg in syscall.args %}
				{{arg.emit_memcpy_ptr_to_temp()}}
				{%- endfor %}
			}
			PPP_RUN_CB(on_{{syscall.name}}_return, {{syscall.cargs}}) ;
		}; break;
		{%- endfor %}
		default:
			PPP_RUN_CB(on_unknown_sys_return, cpu, pc, ctx->no);
	}
	PPP_RUN_CB(on_all_sys_return, cpu, pc, ctx->no);
	PPP_RUN_CB(on_all_sys_return2, cpu, pc, call, ctx);
#endif
}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
