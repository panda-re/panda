Plugin: ida_taint2
===========

Summary
-------

`ida_taint2` is the successor to `ida_taint`, and likewise annotates an IDA database with informatoin about tainted instructions. It has been updated, however, so that it uses [pandalog](docs/pandalog.md) and `taint2`. 

The `ida_taint2.py` IDA script can be used to parse the resulting pandalog and annotate the IDA database.

Note that `ida_taint2.py` currently only supports Windows 7 32-bit replays.

Arguments
---------

None.

Dependencies
------------

Depends on `taint2` to collect tainted instruction information, `callstack_instr` to save information about calling functions, and `win7proc` to log information about what processes are running in the replay.

APIs and Callbacks
------------------

None.

Example
-------

Running against Windows 7 32-bit, saving information to `foo.plog`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda 'syscalls2:profile=windows7_x86;ida_taint2' \
        -panda win7proc -pandalog foo.plog
