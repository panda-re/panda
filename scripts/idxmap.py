#!/usr/bin/env python

import sys
import numpy as np
import struct

if len(sys.argv) != 3:
    print >> sys.stderr, "usage: %s <tap_index> <offset_list>" % sys.argv[0]
    print >> sys.stderr, "  <offset_list> should be a file with offsets into the memory dump, one per line"
    sys.exit(1)

f = open(sys.argv[1], 'rb')
ulong_size = struct.unpack("<I", f.read(4))[0]
dt = '<4u8' if ulong_size == 8 else '<4u4'
idx = np.fromfile(f, dtype=dt)
offsets = np.zeros(idx.shape[0]+1,dtype=np.uint64)
offsets[1:] = np.cumsum(idx[:,3])

x = np.array([int(line,0) for line in open(sys.argv[2])])
found = np.searchsorted(offsets, x, side='right') - 1

for row in idx[found]:
    print "%08x %08x %08x" % (row[0], row[1], row[2]) 
