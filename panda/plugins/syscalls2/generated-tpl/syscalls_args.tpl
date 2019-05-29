/*!
 * @file syscall_args.h
 *
 * @brief Macros that declare local variables for system call arguments and
 * copy their values into them. The purpose of this is to avoid having to
 * manually write the boilerplate code that copies arguments from syscall_ctx_t
 * structs to a local variable with a meaningful name.
 *
 * @note: For macros generating c++ references we use `reinterpret_cast`
 * instead of c-style casting. The latter will discard any `const` specifier
 * of the used `ctx` pointer. This happens silently, so it may result in
 * unexpected side-effects.
 * Using `reinterpret_cast` solves this, as it will raise an error if
 * the `const` qualifier is casted away. This also means that we need to
 * have two sets of macros generating references: one for when `ctx` is
 * declared `const syscall_ctx_t *` and one for when it is declared
 * `syscall_ctx_t *`.
 */
#pragma once
#include "panda/plugin.h"

{%- for platform in syscalls %}
{%- set os, arch = platform.split(':') %}
{%- set divider = ("### %s " % (platform)).ljust(70, "#") %}
{%- set macro_prefix_local = 'locals_%s' % '__'.join(platform.split(':')).upper() %}
{%- set macro_prefix_reference = 'references_%s' % '__'.join(platform.split(':')).upper() %}

/* {{divider}} */
{%- for s in syscalls[platform] %}
// {{s.rettype}} {{s.name}} {{s.args_raw}}
{%- if s.args %}
#define {{macro_prefix_local}}_{{s.name}}(ctx, pref) \
{%- for arg in s.args %}
	{{arg.emit_local_declaration('ctx', 'pref##')}}
	{%- if not loop.last %} \{% endif %}
{%- endfor %}
#if defined(__cplusplus)
#define {{macro_prefix_reference}}_{{s.name}}(ctx, pref) \
{%- for arg in s.args %}
	{{arg.emit_reference_declaration('ctx', 'pref##', const=False)}}
	{%- if not loop.last %} \{% endif %}
{%- endfor %}
#define c{{macro_prefix_reference}}_{{s.name}}(ctx, pref) \
{%- for arg in s.args %}
	{{arg.emit_reference_declaration('ctx', 'pref##', const=True)}}
	{%- if not loop.last %} \{% endif %}
{%- endfor %}
#endif
{% else %}
#undef {{macro_prefix_local}}_{{s.name}}
#if defined(__cplusplus)
#undef {{macro_prefix_reference}}_{{s.name}}
#endif
{% endif %}
{%- endfor %}

{%- endfor %}

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
