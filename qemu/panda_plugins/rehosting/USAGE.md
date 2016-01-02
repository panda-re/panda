Plugin: rehosting
===========

Summary
-------

The `rehosting` plugin is intended to make it easier to get a custom architecture up and running by allowing one to load an arbitrary file (e.g. a raw firmware image) into memory and execute it. This can be slightly simpler than having to modify QEMU's loader, which is somewhat specialized for ELF executables and Linux.

Arguments
---------

* `kernel`: string, no default. The filename that should be loaded into memory.
* `base`: ulong, no default. Where in guest memory (physical address) the file should be loaded.
* `entry`: ulong, no default. The entry point (physical address) where execution should begin.

Dependencies
------------

None.

APIs and Callbacks
------------------

None.

Example
-------

To load a kernel named `foo.bin` at `0x10000` and begin execution at `0x10100`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda rehosting:kernel=foo.bin,base=0x10000,entry=0x10100

Bugs
----

Currently only supports 32-bit x86.
