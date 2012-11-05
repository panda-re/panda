#!/usr/bin/env python

import sys
import time

file = open(sys.argv[1])

while 1:
    where = file.tell()
    line = file.readline()
    if not line:
        time.sleep(.1)
        file.seek(where)
    else:
        caller, pc, cr3, addr, n, val = line.strip().split()
        caller = int(caller, 16)
        pc = int(pc, 16)
        cr3 = int(cr3, 16)
        addr = int(addr, 16)
        val = val.decode('hex')
        sys.stdout.write(val)
        #sys.stdout.flush()
