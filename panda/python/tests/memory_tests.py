#!/usr/bin/env python3

#REMOVE FOR COMMIT vv
import sys
sys.path.insert(1, '/out/panda/panda/panda/python/core')
#REMOVE FOR COMMIT ^^

from pandare import Panda
from sys import argv

#Tests for memory_read/memory_write functions
#There are many implicit uses of those functions in this code as well

arch = argv[1] if len(argv) > 1 else "i386"
panda = Panda(generic=arch)

virt_mem_write=False
virt_mem_read=False
virt_mem_write_bad=False
virt_mem_read_bad=False
phys_mem_write=False
phys_mem_read=False

@panda.ppp("syscalls2", "on_sys_write_enter")
def on_sys_write(cpu, pc, fd, buf, count):
    global virt_mem_write
    global virt_mem_read
    global virt_mem_write_bad
    global virt_mem_read_bad
    global phys_mem_write
    global phys_mem_read

    proc = panda.plugins['osi'].get_current_process(cpu)
    if b'ls' not in panda.ffi.string(proc.name):
        return

    try:
        b = panda.virtual_memory_read(cpu, buf, count)
        s = b.decode('utf8')
    except ValueError:
        print("Failed to read virtual memory at 0x{buf:x}")
        return

    if "root" in s:
        #Assumes image has a /root and not a /woot
        virt_mem_read = True
        s = s.replace("root", "woot")
        try:
            panda.virtual_memory_write(cpu, buf, s.encode())
            b = panda.virtual_memory_read(cpu, buf, count)
            if "woot" in b.decode('utf8'):
                virt_mem_write = True

        except ValueError:
            print("Failed to write virtual memory at 0x{buf:x}")
            return

        phys_addr = panda.virt_to_phys(cpu, buf)
         
        try:
            b = panda.physical_memory_read(phys_addr, count)
            s = b.decode('utf8')
        except ValueError:
            print("Failed to read physical memory at 0x{phys_addr:x}")
            return

        #The value we wrote should be present
        if "woot" in s:
            phys_mem_read = True
            s = s.replace("woot", "root")
            try:
                panda.physical_memory_write(phys_addr, s.encode())
                b = panda.physical_memory_read(phys_addr, count)
                if "woot" not in b.decode('utf8'):
                    phys_mem_write = True

            except ValueError:
                print("Failed to write physical memory at 0x{phys_addr:x}")
                return

        #Now try bad accesses and look for appropriate exceptions
        *_, last_mapping = panda.get_mappings(cpu) 
        bad_virt_addr = last_mapping.base + last_mapping.size + 4096

        try:
            b = panda.virtual_memory_read(cpu, bad_virt_addr, 1)
        except ValueError:
            virt_mem_read_bad = True

        try:
            panda.virtual_memory_write(cpu, bad_virt_addr, b'\x00')
        except ValueError:
            virt_mem_write_bad = True

        panda.disable_ppp("on_sys_write")


@panda.queue_blocking
def driver():
    print(panda.revert_sync("root"))
    panda.run_serial_cmd("ls /")
    panda.end_analysis()

panda.run()

assert(virt_mem_read), "Virtual memory read failed"
assert(virt_mem_write), "Virtual memory write failed"
assert(phys_mem_read), "Physical memory read failed"
assert(phys_mem_write), "Physical memory write failed"
assert(virt_mem_read_bad), "Bad virtual memory read failed to raise exception"
assert(virt_mem_write_bad), "Bad virtual memory write failed to raise exception"
