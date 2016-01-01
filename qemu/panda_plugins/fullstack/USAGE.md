Plugin: fullstack
===========

Summary
-------

`fullstack` takes a list of tap points (a triple of caller, PC, and address space) and logs the full callstack for each tap point at the first point in the replay that it's seen. (The plugin should perhaps be changed so that it prints out full stack information *every* time the tap point is encountered, but that's not what it does right now.)

The input to the plugin is a file named `tap_points.txt`, which contains a list of tap points (caller, PC, address space; each in hex). The output is placed in `tap_callstacks.txt`. Neither the input or output filenames are currently configurable.

Arguments
---------

None.

Dependencies
------------

`fullstack` uses the `callstack_instr` plugin to get its callstack information.

APIs and Callbacks
------------------

None.

Example
-------

Given a file named `tap_points.txt` that looks like:

    8269669d 3302e1de 3eb5b3c0
    68163f03 6815b283 3eb5b180

Run:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda callstack_instr -panda fullstack
