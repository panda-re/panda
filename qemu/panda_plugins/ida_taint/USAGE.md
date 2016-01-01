Plugin: ida_taint
===========

Summary
-------

The `ida_taint` plugin creates a `ida_taint.json` file that can be used, in conjunction with the `ida_taint.py` script, to annotate an IDA database by marking instructions and functions that handle tainted data.

**Warning**: `ida_taint` currently relies on the older `taint` plugin, which is now deprecated. It also only currently works with Windows 7 32-bit, as it relies on an OS-specific method of getting the current process's base address.

Arguments
---------

None.

Dependencies
------------

Depends on the `taint` plugin to provide information about when instructions that handle tainted data are executed, and the `osi` plugin to get the currently running process.

APIs and Callbacks
------------------

None.

Example
-------

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda taint:tainted_instructions=1 -panda osi -panda win7x86intro \
        -panda ida_taint
