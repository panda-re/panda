Plugin: textfinder
===========

Summary
-------

The `textfinder` plugin writes out a report of memory writes, grouped by tap point, with a histogram of the individual bytes written.

Output is placed in a binary file called `mem_report.bin`. It can be parsed with the following Python code:

```Python
f = open('mem_report.bin')
ulong_size = unpack("<i", f.read(4))[0]
ulong_fmt = '<u%d' % ulong_size
print >>sys.stderr, "target_ulong size: %d" % ulong_size
print >>sys.stderr, "Loading data...",
rectype = np.dtype( [ ('caller', ulong_fmt), ('pc', ulong_fmt), ('cr3', ulong_fmt), ('hist', '<I4', 256) ] )
data = np.fromfile(f, dtype=rectype)
print >>sys.stderr, "done (%d tap entries loaded)" % data.size
```

**Warning**: `textfinder` is deprecated. Please use `unigrams` instead.

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

    $PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo \
        -panda textfinder
