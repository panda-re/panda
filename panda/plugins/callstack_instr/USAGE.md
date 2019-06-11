Plugin: callstack_instr
===========

Summary
-------

The `callstack_instr` plugin keeps track of function calls and returns as they occur in the guest. These are tracked using a shadow call stack, so it should be more reliable than trying to do a stack walk. The plugin makes this information available through an exposed plugin-plugin interaction API, and offers callbacks to let other plugins be notified.

By default, the callstack entries are segregated based on what address space ID (`asid`) they occur in.  Although this algorithm is the most general, it has been known to categorize entries incorrectly when the recording has multiple threads.  The `stack_type` argument can be used to change to another segregation method.  The `heuristic` method tries to detect thread switches by sudden jumps in the stack pointer.  Like the `asid` technique, it can be used with any guest operating system (OS) and architecture, and it is more accurate, but it also runs more slowly than the other two techniques.  The `threaded` technique uses OS introspection (OSI) support to get the process ID and thread ID and uses them to distinguish between stacks.  It is more accurate than the `asid` and `heuristic` techniques, but requires OSI support for the guest OS, which is not always available.

`callstack_instr` currently requires `Capstone` to be installed so it can disassemble instructions and identify `call`s and `ret`s.

Arguments
---------

* `verbose`: boolean, defaults to false. Whether to output debugging messages.
* `stack_type`: string, defaults to `threaded` if `-os` is specified, and `asid` otherwise. Sets how different stacks are to be distinguished from each other (by `asid`, `heuristic` or `threaded`).

Dependencies
------------

If the `stack_type` is `threaded`, then `callstack_instr` depends upon an introspection provider for the `osi` plugin.

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
// Get up to n callers from the given stack in use at this moment
// Callers are returned in callers[], most recent first
// Return value is the number of callers actually retrieved
uint32_t get_callers(target_ulong *callers, uint32_t n, CPUState *env);

// Get up to n functions from the given stack in use at this moment
// Functions are returned in functions[], most recent first
// Return value is the number of callers actually retrieved
uint32_t get_functions(target_ulong *functions, uint32_t n, CPUState *env);

// Get the current program point: (Caller, PC, stack ID)
// This isn't quite the right place for it, but since it's awkward
// right now to have a "utilities" library, this will have to do
void get_prog_point(CPUState *env, prog_point *p);
```

There are also functions available for getting callstack information in [pandalog format](docs/pandalog.md):

```C
// Create pandalog message for callstack info
Panda__CallStack *pandalog_callstack_create(void);

// Free a Panda__CallStack struct
void pandalog_callstack_free(Panda__CallStack *cs);
```

In addition to the plugin-plugin API noted above, there is one additional function provided in `prog_point.h` for formating a `prog_point` as a string.  It can be called even after the `callstack_instr` plugin has been unloaded:

```C
// Get the stack ID, as a string, from the given program point. The returned
// object must be freed with g_free when it is no longer needed.
char *get_stackid_string(prog_point p);
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
