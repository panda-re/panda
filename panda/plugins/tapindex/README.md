Plugin: tapindex
===========

Summary
-------

The `tapindex` plugin creates an index listing how many bytes are read or written by each tap point. This index can then be used in conjunction with the `memdump` plugin to quickly search for patterns read from or written to memory and map them back to individual tap points.

The plugin creates two files, `tap_reads.idx` and `tap_writes.idx`. Once you have both a memory dump (`tap_reads.bin` and `tap_writes.bin`) and the index files, you can map offsets in the dump to tap points using `scripts/idxmap.py` (see the Example section for an example of its use).

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

Generate an index:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda tapindex

Then dump memory with `memdump`:

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda memdump

Now search for something in the memory reads dump and store the offsets where it's found into a file named `foo_offsets.txt`:

    grep -bao 'foo' tap_reads.bin | cut -d: -f1 > foo_offsets.txt

And finally, we can map that back to individual tap points with:

    scripts/idxmap.py tap_reads.idx foo_offsets.txt
