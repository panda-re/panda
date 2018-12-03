Plugin: tainted_instr
===========

Summary
-------

The `tainted_instr` plugin provides data about what instructions in a replay handle tainted data.

Arguments
---------

* `summary`: boolean. Determines whether full or summary information will be produced. In summary mode, `tainted_instr` just produces information about what instructions were tainted in each address space seen. In full mode, a log entry is written every time an instruction handling tainted data is executed, along with the callstack at that point. The logs for full mode can get rather large.
* `num`: uint64.  Number of tainted instructions to log or summarize.  The default (0) means there is no limit.  Note that if `tainted_instr` sees the same tainted block reported mutiple times in a row, that this is counted as only one 'instruction'.  For example, if taint change reports come in five times for tainted data in block 1, then three times for tainted data in block 2, then seven times for tainted data in block 1 again, and then four times for tainted data in block 3, then the number of tainted 'instructions' seen will be 4, as there were four distinct runs.

Dependencies
------------

`tainted_instr` uses `taint2` to track taint, and `callstack_instr` to provide callstack information whenever tainted instructions are encountered.

APIs and Callbacks
------------------

None.

Example
-------

To taint data from a file named `foo.dat` on Linux and then find out what instructions handle tainted data from that file, placing output into the pandalog `foo.plog`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda osi \
        -panda osi_linux:kconf_group=debian-3.2.63-i686 \
        -panda syscalls2:profile=linux_x86 \
        -panda file_taint:filename=foo.dat \
        -panda tainted_instr \
        -pandalog foo.plog
