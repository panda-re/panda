#pragma once

#include <stdbool.h>

// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

target_ulong get_id(CPUState *cpu);

bool id_is_initialized(void);

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!
/* vim:set tabstop=4 softtabstop=4 expandtab: */
