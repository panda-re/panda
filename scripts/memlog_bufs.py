#!/usr/bin/env python

import sys
import fileinput

buf = ''
prev_addr = -1

for line in sys.stdin:
    caller, pc, cr3, addr, n, val = line.strip().split()
    caller = int(caller, 16)
    pc = int(pc, 16)
    cr3 = int(cr3, 16)
    addr = int(addr, 16)
    val = val.decode('hex')
    if buf and addr != prev_addr + 1:
        print buf.decode('utf-16-le',errors='backslashreplace').encode('ascii',errors='backslashreplace')
        #print buf.encode('hex')
        sys.stdout.flush()
        buf = ''
    prev_addr = addr
    buf += val

#if buf: print buf.encode('hex')
if buf: print buf.decode('utf-16-le',errors='backslashreplace').encode('ascii',errors='backslashreplace')
