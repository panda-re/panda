// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

{%- for syscall_name, syscall in syscalls|dictsort %}
#ifndef TYPEDEFS_PPP_SYSCALL_ON_{{syscall.name|upper}}_ENTER
#define TYPEDEFS_PPP_SYSCALL_ON_{{syscall.name|upper}}_ENTER 1
PPP_CB_TYPEDEF(void, on_{{syscall.name}}_enter, {{syscall.cargs_signature}});
#endif
#ifndef TYPEDEFS_PPP_SYSCALL_ON_{{syscall.name|upper}}_RETURN
#define TYPEDEFS_PPP_SYSCALL_ON_{{syscall.name|upper}}_RETURN 1
PPP_CB_TYPEDEF(void, on_{{syscall.name}}_return, {{syscall.cargs_signature}});
#endif
{%- endfor %}

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

