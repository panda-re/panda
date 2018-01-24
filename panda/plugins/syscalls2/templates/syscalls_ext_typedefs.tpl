{%- for arch, syscalls in syscalls_arch|dictsort -%}
#ifdef {{architectures[arch].qemu_target}}
{%- for syscall_name, syscall in syscalls|dictsort %}
typedef void (*on_{{syscall.name}}_enter_t)({{syscall.cargs_signature}});
typedef void (*on_{{syscall.name}}_return_t)({{syscall.cargs_signature}});
{%- endfor %}
#endif
{% endfor %}
typedef void (*on_all_sys_enter_t)(CPUState *cpu, target_ulong pc, target_ulong callno);
typedef void (*on_all_sys_return_t)(CPUState *cpu, target_ulong pc, target_ulong callno);
typedef void (*on_unknown_sys_enter_t)(CPUState *cpu, target_ulong pc, target_ulong callno);
typedef void (*on_unknown_sys_return_t)(CPUState *cpu, target_ulong pc, target_ulong callno);

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
