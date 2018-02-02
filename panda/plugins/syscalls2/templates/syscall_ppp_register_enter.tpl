{%- for arch, syscalls in syscalls_arch|dictsort -%}
#ifdef {{architectures[arch].qemu_target}}
{%- for syscall_name, syscall in syscalls|dictsort %}
PPP_PROT_REG_CB(on_{{syscall.name}}_enter)
{%- endfor %}
#endif
{% endfor %}
PPP_PROT_REG_CB(on_unknown_sys_enter)
PPP_PROT_REG_CB(on_all_sys_enter)

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
