#!/usr/bin/env python

import sys
import time

filemap = {}

f = open(sys.argv[1])
for line in f:
    caller, pc, cr3, addr, n, val = line.strip().split()
    fname = sys.argv[2] + "." + ".".join( (caller, pc, cr3) ) + ".dat"
    if fname not in filemap:
        filemap[fname] = open(fname,'w')

    val = val.decode('hex')
    filemap[fname].write(val)
