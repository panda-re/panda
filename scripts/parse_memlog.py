#!/usr/bin/env python

import sys
import fileinput
from collections import defaultdict
from pprint import pprint

def coalesce(mem):
    data = {}
    start = 0
    buf = ""
    for i in sorted(mem):
        if not buf: start = i
        buf += mem[i]
        if i+1 not in mem:
            data[start] = buf
            buf = ""
    return data

def dump_mem(coalesced):
    for start, buf in coalesced.items():
        print hex(start),":",buf

shadow_mem = defaultdict(list)

for line in fileinput.input():
    pc, addr, val = line.strip().split()
    pc = int(pc, 16)
    addr = int(addr, 16)
    val = val.decode('hex')
    shadow_mem[pc].append((addr,val))


#from IPython.frontend.terminal.interactiveshell import TerminalInteractiveShell
#shell = TerminalInteractiveShell(user_ns=locals())
#shell.mainloop()

for eip in shadow_mem:
    print "==== %#010x ====" % eip
    pprint(coalesce(dict(shadow_mem[eip])))
