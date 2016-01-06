Plugin: useafterfree
===========

Summary
-------

The `useafterfree` plugin implements a simple use-after-free detector. It tracks calls to low-level
memory allocation functions (e.g., `RtlAllocateHeap`, `RtlFreeHeap`, and `RtlReAllocateHeap` on Windows), and it maintains shadow lists of allocated and freed memory. When a pointer to freed memory is dereferenced, a use-after-free has occurred and the plugin detects it.

Note that this approach produces some false negatives since a new allocation may have since occupied the free space.

Arguments
---------

* `alloc`: ulong, defaults to 0x7787209D. The virtual address of the `malloc` function.
* `free`: ulong, defaults to 0x77871F31. The virtual address of the `free` function.
* `realloc`: ulong, defaults to 0x77877E54. The virtual address of the `realloc` function.
* `cr3`, ulong, defaults to 0x3F98B320. The CR3 (address space) we should watch. `useafterfree` will only try to detect use-after-free bugs inside this address space.
* `word`: uint64, defaults to 4. The native word size on the target operating system, in bytes.

Dependencies
------------

The `useafterfree` plugin uses `callstack_instr` to intercept function call returns.

APIs and Callbacks
------------------

None.

Example
-------

Looking for a use-after-free with `malloc` at `0x12000`, `free` at `0x13000`, and `realloc` at `0x14000`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda callstack_instr \
        -panda useafterfree:alloc=0x12000,free=0x13000,realloc=0x14000

See the [UAF tutorial](../../../docs/UAF.md) for a full tutorial on using this plugin to diagnose a use-after-free vulnerability in Internet Explorer.

Bugs
----

False negatives if a new allocation is made before the pointer to a freed region is dereferenced.

Currently only supports the `x86_64` target, even though it should be easy to generalize to other architectures.
