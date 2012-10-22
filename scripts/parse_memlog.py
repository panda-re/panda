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
    caller, pc, cr3, addr, n, val = line.strip().split()
    caller = int(caller, 16)
    pc = int(pc, 16)
    cr3 = int(cr3, 16)
    addr = int(addr, 16)
    val = val.decode('hex')
    shadow_mem[caller,pc,cr3].append((addr,val))


#from IPython.frontend.terminal.interactiveshell import TerminalInteractiveShell
#shell = TerminalInteractiveShell(user_ns=locals())
#shell.mainloop()

for caller,eip,cr3 in shadow_mem:
    print "==== %#010x (CR3: %#010x Caller: %#010x) ====" % (eip, cr3, caller)
    pprint(coalesce(dict(shadow_mem[caller,eip,cr3])))
