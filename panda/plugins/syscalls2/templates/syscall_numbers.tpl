/*!
 * @file syscall_numbers.h
 *
 * @brief Symbolic names for syscall numbers. We make this header c++ only
 * so we can use namespaces. This results in shorter names in the code and
 * avoids polluting the preprocessor namespace.
 */
#pragma once
#if !defined(__cplusplus)
#else
namespace syscalls2 {
	{%- for p in syscalls %}
	{%- set os, arch = p.split(':') %}
	// {{p}}
	namespace {{os}} {
		namespace {{arch}} {
			{%- for s in syscalls[p] %}
			const int {{s.name}} = {{s.no}};
			{%- endfor %}
		}
	}
	{%- endfor %}
}
#endif

/* vim: set tabstop=4 softtabstop=4 noexpandtab ft=cpp: */
