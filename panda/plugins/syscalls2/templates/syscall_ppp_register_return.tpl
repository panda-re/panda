{%- for arch, syscalls in syscalls_arch|dictsort -%}
#ifdef {{architectures[arch].qemu_target}}
{%- for syscall_name, syscall in syscalls|dictsort %}
PPP_PROT_REG_CB(on_{{syscall.name}}_return)
{%- endfor %}
#endif
{% endfor %}
#if 1
PPP_PROT_REG_CB(on_unknown_sys_return)
PPP_PROT_REG_CB(on_all_sys_return)
#endif
