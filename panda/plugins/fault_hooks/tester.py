#!/usr/bin/env python3
from sys import argv
from pandare import Panda
from rich import print
import capstone
from time import sleep

# Single arg of arch, defaults to i386
arch = "mips" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

if arch == "mips":
    # on mips you need to load OSI early so r28 can be estalished
    panda.load_plugin("osi")
    panda.load_plugin("osi_linux")

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("LD_SHOW_AUXV=1 uname -a",no_timeout=True))
    print(panda.run_serial_cmd("sleep 1",no_timeout=True))
    panda.end_analysis()

def hook_thing(address,asid):
    print(f"hooking {asid:#x} {address:#x}")
    @panda.hook_fault(address,asid)
    def hf(cpu, asid, address):
        print(f"got {asid:#x} {address:#x} @ {panda.current_pc(cpu):#x}")
        print(f"bytes: {panda.virtual_memory_read(cpu, address, 20)}")

mapp = {}

def neg_1():
    if arch == "arm" or arch == "i386" or arch == "mips":
        return 0xffffffff
    else:
        return 0xffffffffffffffff

@panda.ppp("proc_start_linux", "on_rec_auxv")
def recv_auxv(cpu, tb, auxv):
    procname = panda.ffi.string(auxv.execfn)
    print(f"started proc {procname} {auxv.phdr:#x} {auxv.entry:#x}")
    entry = auxv.entry
    asid = panda.current_asid(cpu)
    global mapp
    mapp[asid] = []
    panda.disable_ppp("recv_auxv")
    for mapping in panda.get_mappings(cpu):
        name = panda.ffi.string(mapping.name)
        if panda.virt_to_phys(cpu,mapping.base) == neg_1():
            print(f"{name} {mapping.base:#x}-{mapping.base+mapping.size:#x} {asid:#x}")
            hook_thing(mapping.base, asid)
            mapp[asid].append((name, asid, mapping.base, mapping.size))

# @panda.ppp("syscalls2","on_sys_execve_enter")
def execve(cpu, *args):
    import ipdb
    ipdb.set_trace()

@panda.ppp("syscalls2","on_sys_exit_group_enter")
def sys_exit(cpu, pc, *args):
    print("At end of program")
    asid = panda.current_asid(cpu)
    for mapping in panda.get_mappings(cpu):
        name = panda.ffi.string(mapping.name)
        if panda.virt_to_phys(cpu,mapping.base) == neg_1():
            print(f"{name} {mapping.base:#x} {asid:#x} unmapped")

# panda.load_plugin("fault_hooks")
panda.run()