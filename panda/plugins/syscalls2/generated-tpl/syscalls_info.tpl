#include <stdint.h>
#include <stdbool.h>
#include "../syscalls2_info.h"
#define MAX_SYSCALL_NO {{max_syscall_no}}
#define MAX_SYSCALL_GENERIC_NO {{max_syscall_generic_no}}
#define MAX_SYSCALL_ARGS {{max_syscall_args}}

#if !defined(__clang__) && __GNUC__ < 5
#if 0
	The system call arguments array has variable size.
	This prevents initializing the whole syscall_info statically.
	To solve this, we declare static variables for the arguments
	array of all system calls and assign those instead.
	***This solution may be gcc-specific!***

	See: https://stackoverflow.com/a/24640918
#endif
#warning This file may require gcc-5 or later to be compiled.
#endif

{% for syscall in syscalls -%}
{% if syscall.generic -%}
static syscall_argtype_t argt_{{syscall.no}}[] = {
	{%- for arg in syscall.args -%}
	SYSCALL_ARG_{{arg.type}}{{ ', ' if not loop.last else ''}}
	{%- endfor -%}
};
static uint8_t argsz_{{syscall.no}}[] = {
	{%- for arg in syscall.args -%}
	sizeof({{arg.ctype}}){{ ', ' if not loop.last else ''}}
	{%- endfor -%}
};
static const char* const argn_{{syscall.no}}[] = {
	{%- for arg in syscall.args -%}
	"{{arg.name}}"{{ ', ' if not loop.last else ', 0'}}
	{%- endfor -%}
};
static const char* const argtn_{{syscall.no}}[] = {
	{%- for arg in syscall.args -%}
	"{{arg.struct_name}}"{{ ', ' if not loop.last else ', 0'}}
	{%- endfor -%}
};
{% else -%}
/* skipping non generic system call {{syscall.no}} ({{syscall.name}}) */
{% endif %}
{%- endfor %}

syscall_info_t __syscall_info_a[] = {
	/* note that uninitialized values will be zeroed-out */
	{% for syscall in syscalls -%}
	{% if syscall.generic -%}
	[{{syscall.no}}] = {
		.no = {{syscall.no}},
		.name = "{{syscall.name}}",
		.nargs = {{syscall.args|length}},
		.argt = argt_{{syscall.no}},
		.argsz = argsz_{{syscall.no}},
		.argn = argn_{{syscall.no}},
		.argtn = argtn_{{syscall.no}},
		.noreturn = {{ 'true' if syscall.panda_noreturn else 'false' }}
	},
	{% else -%}
	/* skipping non generic system call {{syscall.no}} ({{syscall.name}}) */
	{% endif %}
	{%- endfor %}
};

syscall_meta_t __syscall_meta = {
	.max = MAX_SYSCALL_NO,
	.max_generic = MAX_SYSCALL_GENERIC_NO,
	.max_args = MAX_SYSCALL_ARGS
};

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=c: */
