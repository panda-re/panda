#!/usr/bin/env python3
from sys import argv
from pandare import Panda
from rich import print
import capstone
from time import sleep

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a",no_timeout=True))
    print(panda.run_serial_cmd("whoami",no_timeout=True))
    print(panda.run_serial_cmd("cat /etc/passwd",no_timeout=True))
    print(panda.run_serial_cmd("lsmod",no_timeout=True))
    panda.end_analysis()

def disas(cpu, tb, pc):
    code = panda.virtual_memory_read(cpu, tb.pc, tb.size)
    vals = []
    for i in md.disasm(code, tb.pc):
        if i.address >= pc:
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            vals.append(i.address)
    return vals

def do_hook(pc):
    @panda.hook3(pc)
    def av2(cpu, tb, h):
        print(f"Got Hook @{h.pc:#x}")
        disas(cpu,tb,h.pc)
        return True
        # sleep(1)

@panda.ppp("proc_start_linux", "on_rec_auxv")
def recv_auxv(cpu, tb, auxv):
    procname = panda.ffi.string(auxv.execfn)
    print(f"started proc {procname} {auxv.phdr:#x} {auxv.entry:#x}")
    entry = auxv.entry
    @panda.hook3(auxv.entry,asid=None,always_starts_block=True)
    def av(cpu, tb, h):
        print(f"Made it to start of block at: {h.pc:#x}")
        # import ipdb
        # ipdb.set_trace()
        for a in disas(cpu,tb,h.pc)[1:]:
            print(f"Hooking instructions: {a:#x}")
            do_hook(a)
        
        print("[bold yellow] ABOUT TO INSERT OUR HOOKS AND RUN [bold yellow]")
        print("[bold yellow] WATCH THE DISASSEMBLY GET SMALLER EACH ROUND [bold yellow]")
        # return True
        # sleep(3)

panda.enable_precise_pc()
print("[bold red]This output is artificially slowed for readability[bold red]")
panda.run()