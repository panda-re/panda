Plugin: pri_simple
===========

Summary
-------

The `pri_simple` plugin is an example of using `pri` and a `pri` provider to query source level constructs
during a PANDA replay.
`pri_simple` registers a callback on every line change (in the source code) during the life time of a process
we have symbol information for.
On these line changes, the plugin will print line and variable information.
The plugin also demonstrates using `pri_get_vma_symbol` with virtual mem read/write callbacks.

Arguments
---------

NONE

Dependencies
------------

`pri_simple` depends on the **pri** and **pri_dwarf** plugins in order to get information about line changes and live variable information during an executable replay.

APIs and Callbacks
------------------

None.

Example
-------

Here is an example run of the `pri_simple` plugin:

    ~/git/panda/qemu/i386-softmmu/qemu-system-i386 \
        -replay "/path/to/replaylog" \
        -panda osi \
        -panda osi_linux:kconf_file=/path/to/kconf,kconf_group=debian-3.2.51-i686 \
        -panda pri \
        -panda pri_dwarf:proc="procname",g_debugpath="/path/to/dbg/",h_debugpath="/path/to/hostdbg" \
        -panda pri_simple \
        -pandalog foo.plog

