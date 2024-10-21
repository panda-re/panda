{%- for arch, syscalls in syscalls_arch.items() -%}
#if {{architectures[arch].get('boilerplate_target', architectures[arch].qemu_target)}}
{%- for syscall_name, syscall in syscalls|dictsort %}
#ifndef PPP_CB_BOILERPLATE_ENTER_ON_{{syscall.name|upper}}_RETURN
#define PPP_CB_BOILERPLATE_ENTER_ON_{{syscall.name|upper}}_RETURN
PPP_CB_BOILERPLATE(on_{{syscall.name}}_return)
#endif
{%- endfor %}
#endif
{% endfor %}
PPP_CB_BOILERPLATE(on_unknown_sys_return)
PPP_CB_BOILERPLATE(on_all_sys_return)
PPP_CB_BOILERPLATE(on_all_sys_return2)

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
