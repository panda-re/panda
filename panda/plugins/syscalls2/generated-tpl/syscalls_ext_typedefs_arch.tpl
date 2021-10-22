// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

{%- for syscall_name, syscall in syscalls|dictsort %}
PPP_CB_TYPEDEF(void, on_{{syscall.name}}_enter, {{syscall.cargs_signature}});
PPP_CB_TYPEDEF(void, on_{{syscall.name}}_return, {{syscall.cargs_signature}});
{%- endfor %}

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

