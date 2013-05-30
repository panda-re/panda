#!/usr/bin/env python

import gzip
import sys
import time

filemap = {}

if sys.argv[1].endswith('.gz'):
    f = gzip.GzipFile(sys.argv[1])
else:
    f = open(sys.argv[1])

for line in f:
    # Avoid "too many open files" -- flush the file descriptor map
    if len(filemap) > 1000:
        for o in filemap.values(): o.close()
        filemap = {}

    callers, pc, cr3, addr, n, val = line.strip().rsplit(" ", 5)
    callers = callers.split()
    fname = sys.argv[2] + "." + ".".join( callers[-1:] + [pc, cr3] ) + ".dat"
    if fname not in filemap:
        filemap[fname] = open(fname,'a')

    val = val.decode('hex')
    filemap[fname].write(val)
