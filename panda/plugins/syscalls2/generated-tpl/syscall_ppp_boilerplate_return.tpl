{%- for arch, syscalls in syscalls_arch|dictsort -%}
#if {{architectures[arch].qemu_target}}
{%- for syscall_name, syscall in syscalls|dictsort %}
PPP_CB_BOILERPLATE(on_{{syscall.name}}_return)
{%- endfor %}
#endif
{% endfor %}
PPP_CB_BOILERPLATE(on_unknown_sys_return)
PPP_CB_BOILERPLATE(on_all_sys_return)
PPP_CB_BOILERPLATE(on_all_sys_return2)

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
