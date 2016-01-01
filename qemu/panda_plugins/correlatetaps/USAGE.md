Plugin: correlatetaps
===========

Summary
-------

The `correlatetaps` plugin produces a report of which tap points were often seen to be writing to contiguous memory regions in close temporal proximity. The idea is that some tap points may logically belong together (because they read and write the same kind of data) but may be physically spread across multiple instructions.

Produces a binary file with records like:

    [ tap_point1 ][ tap_point2 ][ int count ]

Each tap point is a struct giving the caller, program counter, and address space:

    struct prog_point {
        target_ulong caller;
        target_ulong pc;
        target_ulong cr3;
    };

Arguments
---------

None.

Dependencies
------------

Depends on the `callstack_instr` to get information about the calling context of each memory write.

APIs and Callbacks
------------------

None.

Example
-------

`$PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda callstack_instr -panda correlatetaps`
