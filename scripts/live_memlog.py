#!/usr/bin/env python

import sys
import fileinput

for line in sys.stdin:
    caller, pc, cr3, addr, n, val = line.strip().split()
    caller = int(caller, 16)
    pc = int(pc, 16)
    cr3 = int(cr3, 16)
    addr = int(addr, 16)
    val = val.decode('hex')
    sys.stdout.write(val)
    sys.stdout.flush()
