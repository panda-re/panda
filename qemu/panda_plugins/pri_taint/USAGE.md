Plugin: pri_taint
===========

Summary
-------

The `pri_taint` plugin registers a callback on every line change during the life time of a process we have DWARF information for.  On these line changes, the plugin will query taint on the memory locations of variables that are live at that point.

Arguments
---------

NONE

Dependencies
------------

`pri_taint` depends on the **pri** and **pri_dwarf** plugins in order to get information about line changes and live variable information during an executable replay.

APIs and Callbacks
------------------

None.

Example
-------

Here is an example run of the `pri_taint` plugin using the `file_taint` plugin.

    ~/git/panda/qemu/i386-softmmu/qemu-system-i386 \
        -replay "/path/to/replaylog" \
        -panda osi \
        -panda osi_linux:kconf_file=/path/to/kconf,kconf_group=debian-3.2.51-i686 \
        -panda pri \
        -panda pri_dwarf:proc="procname",g_debugpath="/path/to/dbg/",h_debugpath="/path/to/hostdbg" \
        -panda file_taint:filename="taintedfile" \
        -panda pri_taint \
        -pandalog foo.plog

