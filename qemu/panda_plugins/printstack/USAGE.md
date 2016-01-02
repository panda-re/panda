Plugin: printstack
===========

Summary
-------

The `printstack` plugin simply prints out the stack of called functions whenever a particular program counter is reached.

Arguments
---------

* `pc`: ulong, no default. The program counter for which we'd like to dump out the call stack.

Dependencies
------------

`printstack` relies on the `callstack_instr` plugin to get the call stack.

APIs and Callbacks
------------------

None.

Example
-------

To print out the list of calling functions whenever the program counter `0x124400` is reached:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda callstack_instr -panda printstack:pc=0x124400

Bugs
----

Only checks the program counter at the start of a basic block, so if the program counter you're looking for is in the middle of a basic block it may be skipped.
