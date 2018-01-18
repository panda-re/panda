{%- for arch, syscalls in syscalls_arch|dictsort -%}
#ifdef {{architectures[arch].qemu_target}}
{%- for syscall_name, syscall in syscalls|dictsort %}
PPP_CB_EXTERN(on_{{syscall.name}}_return)
{%- endfor %}
#endif
{% endfor %}
#if 1
PPP_CB_EXTERN(on_unknown_sys_return)
PPP_CB_EXTERN(on_all_sys_return)
#endif
