Plugin: memstats
===========

Summary
-------

The `memstats` plugin simply keeps track of how many memory loads and stores were performed during a replay, and a count of how many bytes were read and written to memory. At the end of the replay it will print out a simple status line, such as:

    Memory statistics: 2314151222 loads, 212478222 stores, 9071472790 bytes read, 875410274 bytes written.

Arguments
---------

None.

Dependencies
------------

None.

APIs and Callbacks
------------------

None.

Example
-------

To get the memory statistics:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda memstats
