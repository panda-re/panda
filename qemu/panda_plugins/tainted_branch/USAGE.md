Plugin: tainted_branch
===========

Summary
-------

The `tainted_branch` plugin produces a report in pandalog format that lists the addresses of every branch instruction in the replay that depends on tainted data. This can be very useful for doing things like determining what parts of the program can be influenced by user input.

Arguments
---------

None.

Dependencies
------------

`tainted_branch` uses `taint2` to track taint, and `callstack_instr` to provide callstack information whenever tainted branches are encountered.

APIs and Callbacks
------------------

None.

Example
-------

To taint data from a file named `foo.dat` on Linux and then find out what branches depend on data from that file, placing output into the pandalog `foo.plog`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda osi \
        -panda osi_linux:kconf_group=debian-3.2.63-i686 \
        -panda syscalls2:profile=linux_x86 \
        -panda file_taint:filename=foo.dat \
        -panda tainted_branch \
        -pandalog foo.plog

