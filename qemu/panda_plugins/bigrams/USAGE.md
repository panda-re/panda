Plugin: bigrams
===========

Summary
-------

This plugin collects bigram byte statistics on the memory writes (FIXME: should add reads as well) for all tap points in a replay. This allows one to do things like cluster tap points, search for tap points based on statistical information about the kind of data.

Outputs a file called `bigram_mem_report.bin` that can be parsed using the following snippet of Python:

    f = open("bigram_mem_report.bin")
    ulong_size = struct.unpack("<i", f.read(4))[0]
    ulong_fmt = '<u%d' % ulong_size
    FMT = "%%0%dx" % (ulong_size*2)

    rec_hdr = np.dtype( [ ('caller', ulong_fmt), ('pc', ulong_fmt), ('cr3', ulong_fmt), ('nbins', '<I4') ] )
    hist_entry = [ ('key', '<H'), ('value', '<u4') ]

    meta = []
    data = []
    rows = []
    cols = []

    print >>sys.stderr, "Parsing file..."
    i = 0
    while True:
        hdr = np.fromfile(f, dtype=rec_hdr, count=1)
        if not hdr: break
        entries = np.fromfile(f, dtype=hist_entry, count=hdr['nbins'])
        # Might happen if a tap only wrote one byte. In that case there's no bigram
        if entries.size == 0: continue
        #print >>sys.stderr, "Parsed entry with %d bins, file offset=%d" % (hdr['nbins'],f.tell())
        cols.extend(entries['key'])
        rows.extend([i]*len(entries))
        data.extend(entries['value'])
        meta.append(hdr)

        i += 1

    f.close()

    print >>sys.stderr, "Parsed", i, "tap points"

Some scripts for working with bigram data can be found in PANDA's `scripts` directory.

For more details, see our paper *Tappan Zee North Bridge: Mining Memory Accesses for Introspection*.

Arguments
---------

None. This should probably be fixed so that at least the output filename can be specified.

Dependencies
------------

Depends on the `callstack_instr` to get information about the calling context of each memory read or write.

APIs and Callbacks
------------------

None.

Example
-------

`$PANDA_PATH/x86_64-softmmu/qemu-system-x86_64 -replay foo -panda callstack_instr -panda bigrams`
