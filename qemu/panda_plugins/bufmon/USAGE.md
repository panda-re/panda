Plugin: bufmon
===========

Summary
-------

The `bufmon` plugin tracks all memory accesses to a particular buffer throughout a replay.

Takes a single input file, `search_buffers.txt`, with the buffers to monitor, one per line in the file. Each buffer is specified by its starting virtual address, size, and address space (all in hexadecimal).

Produces a single output file, `buffer_taps.txt`. Each line gives an indicator of whether the access was a read or a write (`READ` or `WRITE`), the guest instruction count, tap point, virtual address accessed, size of the access, and finally the actual bytes that were read or written.

Arguments
---------

None.

Dependencies
------------

Depends on the `callstack_instr` to get information about the calling context of each memory read or write.

APIs and Callbacks
------------------

None.

Example
-------

To monitor the buffer at `0x10000` of size `0x10` bytes in ASID `0x3f9b2040`, you would create a `search_buffers.txt` that looks like:

    10000 10 3f9b2040

And then run:

`$PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda callstack_instr -panda bufmon`
