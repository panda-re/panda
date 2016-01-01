Plugin: memdump
===========

Summary
-------

The `memdump` plugin dumps the content of all memory reads and writes in a replay out to disk, organized by tap point. This allows one to then use more advanced tools to search through the raw content for interesting data; for example, one could use regular expressions with `grep`, or a binary scanner like `binwalk`, to search through the dumped data.

To operate efficiently, `memdump` requires that a first pass on the replay be made with the `tapindex` plugin. The `tapindex` plugin creates an index listing how much data was read or written by each tap point. Then, `memdump` can allocate each tap point the required amount of space in its output files, `tap_reads.bin` and `tap_writes.bin`. When some data of interest is found in these binary files, one can then look up what tap point it belongs to by consulting the index files.

Note that this plugin does *not* produce memory snapshots usable with forensic memory analysis tools like Volatility or Rekall. For that, see `memsnap` and `memsavep`.

Arguments
---------

None.

Dependencies
------------

The `memdump` plugin has no runtime dependencies. However, it depends on having previously run the `tapindex` plugin, as described in the Summary above.

APIs and Callbacks
------------------

None.

Example
-------

First run `tapindex` to create `tap_reads.idx` and `tap_writes.idx`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda tapindex

Then, run `memdump` to create `tap_reads.bin` and `tap_writes.bin` containing the memory data:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda memdump

Finally, look for some interesting pattern:

    grep -a -o -b "PATTERN" tap_reads.bin tap_writes.bin
