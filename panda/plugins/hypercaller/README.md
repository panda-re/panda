Plugin: `hypercaller`
===========

Summary
-------

This plugin provides an interface for hypercalls from the guest. It establishes a basic interface for those hypercalls and simplifies the interactions.

In particular, it presumes the following:

- There is a single source for a message from a guest hypercall
- The guest hypercall indicates the recipient for that message via a unique magic number
- All magic numbers for interactions are unique

Arguments
---------

This plugin takes no arguments.

Dependencies
------------

This plugin has no external dependencies.

APIs and Callbacks
------------------

The plugin provides a simple interface for external plugins to register and unregister hypercalls. The interface is as follows:

A function within a plugin can register a hypercall with the following signature:
```
typedef void (*hypercall_t)(CPUState *cpu);
```

It then passes a reference to this function to the `register_hypercall` function, along with a unique magic number that will be used to identify the hypercall.
```
void register_hypercall(uint32_t magic, hypercall_t);
```

To unregister a hypercall, the plugin can call the following function with the magic number that was used to register the hypercall:
```
void unregister_hypercall(uint32_t magic);
```

Example
-------

This was designed primarily for Python use cases:

```Python
MAGIC = 0x12345678
@panda.hypercall(MAGIC)
def hypercall(cpu):
    print("Hello from my hypercall!"

```


It's much easier to handle this from Python, but here's an example of how you might use this plugin from a C plugin:



```C
#include <panda/plugin.h>
#include <hypercaller/hypercaller.h>

hypercall_t* register_hypercall;

void my_hypercall(CPUState *cpu) {
    printf("Hello from my hypercall!\n");
}

bool init_plugin(void *self) {
    void *hypercaller = panda_get_plugin_by_name("hypercaller");
    if (hypercaller == NULL){
      panda_require("hypercaller");
      hypercaller = panda_get_plugin_by_name("hypercaller");
    }
    register_hypercall = (hypercall_t*)dlsym(hypercaller, "register_hypercall");
    register_hypercall(0x12345678, my_hypercall);
    return true;
}
```
