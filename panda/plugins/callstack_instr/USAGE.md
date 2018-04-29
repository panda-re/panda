Plugin: callstack_instr
===========

Summary
-------

The `callstack_instr` plugin keeps track of function calls and returns as they occur in the guest. These are tracked using a shadow call stack, so it should be more reliable than trying to do a stack walk. The plugin makes this information available through an exposed plugin-plugin interaction API, and offers callbacks to let other plugins be notified.

`callstack_instr` currently requires `distorm` to be installed so it can disassemble instructions and identify `call`s and `ret`s.

Arguments
---------

None.

Dependencies
------------

None.

APIs and Callbacks
------------------

`callstack_instr` provides the following callbacks:

Name: **on_call**

Signature:

```C
typedef void (* on_call_t)(CPUState *env, target_ulong func)
```

Description: Called every time a function call occurs in the guest. Arguments are the CPU state pointer `env` and the virtual address of the function that is being called.

Name: **on_ret**

Signature:

```C
typedef void (* on_ret_t)(CPUState *env, target_ulong func)
```

Description: Called every time a function call returns in guest (e.g., at the `ret` instruction). Arguments are the CPU state pointer `env` and the virtual address of the function we're returning from. This can be used to match up the return with the appropriate call, but does not indicate the level of nesting in the case of recursive calls. If you want to match returns with calls in this case, you will need to keep a counter inside your plugin.

`callstack_instr` also provides the following API functions that can be called from other plugins:

```C
// Get up to n callers from the given address space at this moment
// Callers are returned in callers[], most recent first
// Return value is the number of callers actually retrieved
uint32_t get_callers(target_ulong *callers, uint32_t n, CPUState *env);

// Get up to n functions from the given address space at this moment
// Functions are returned in functions[], most recent first
// Return value is the number of callers actually retrieved
uint32_t get_functions(target_ulong *functions, uint32_t n, CPUState *env);

// Get the current program point: (Caller, PC, ASID)
// This isn't quite the right place for it, but since it's awkward
// right now to have a "utilities" library, this will have to do
void get_prog_point(CPUState *env, prog_point *p);
```

There are also functions available for getting callstack information in [pandalog format](docs/pandalog.md):

```C
// Create pandalog message for callstack info
Panda__CallStack *pandalog_callstack_create(void);

// Create pandalog message for callstack info
Panda__CallStack *pandalog_callstack_create(void);

// Free a Panda__CallStack struct
void pandalog_callstack_free(Panda__CallStack *cs);
```

Example
-------

`callstack_instr` is not very useful its own. Instead, you can use it from within other plugins, for example:

```C
#include "../callstack_instr/callstack_instr_ext.h"
#include "panda/plugin_plugin.h"

// ...

int some_plugin_fn(CPUState *env) {
    target_ulong callers[16];
    int n;
    n = get_callers(callers, 16, env);
    for (int i = 0; i < n; i++)
        printf("Callstack entry: " TARGET_FMT_lx "\n", callers[i]);
    return 0;
}

// ...

bool init_plugin(void *self) {
    panda_require("callstack_instr");
    if (!init_callstack_instr_api()) return false;
}
```
