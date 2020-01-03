// XXX: pycparser is failing to parse hooks_int_fns.h with the
// typedef'd function pointer.
// However, this file is 's still provided for pypanda although the
// typical panda plugin-to-plugin API isn't automatically created

/*
typedef void hook_func_t
#include "hooks_int_fns.h"
*/
