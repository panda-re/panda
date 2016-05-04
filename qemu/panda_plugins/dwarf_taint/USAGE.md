Plugin: dwarf_taint
===========

Summary
-------

The `dwarf_taint` plugin registers a callback on every line change during the life time of a process we have DWARF information for.  On these line changes, the plugin will query taint on the memory locations of variables that are live at that point.

Arguments
---------

NONE
Dependencies
------------

`dwarf_taint` depends on the **stpi** and **dwarfp** plugins in order to get information about line changes and live variable information during an executable replay.

APIs and Callbacks
------------------

None.

Example
-------

Here is an example run of the `dwarf_taint` plugin using the `dwarf_taint` plugin.
    ~/git/panda/qemu/i386-softmmu/qemu-system-i386 \
        -replay "/path/to/replaylog" \
        -panda osi \
        -panda osi_linux:kconf_file=/path/to/kconf,kconf_group=debian-3.2.51-i686 \
        -panda stpi \
        -panda dwarfp:proc="procname",g_debugpath="/path/to/dbg/",h_debugpath="/path/to/hostdbg" \
        -panda file_taint:filename="taintedfile" \
        -panda dwarf_taint \
        -pandalog foo.plog

