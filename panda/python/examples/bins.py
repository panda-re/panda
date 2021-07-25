#!/usr/bin/env python3
'''
bins.py

This program shows how to make use of the dynamic_symbols plugin.

First, we take a recording (though this could be done live). In this recording
we cat /etc/passwd and run other random commands.

We then use hook_symbols to hook various libc functions. This includes:
    - _Exit
    - __libc_malloc, __libc_calloc, __libc_realloc
    - free
    - write

We then use these functions to track dynamic memory regions created and used.

Run with: python3 bins.py
'''
from pandare import Panda
from sys import argv


# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

from os.path import exists

recording_name = "catetc6"+arch
if not exists(f"{recording_name}-rr-snp"):
    print("taking recording")
    @panda.queue_blocking
    def do_stuff():
        panda.revert_sync("root")
        panda.run_monitor_cmd(f"begin_record {recording_name}")
        print(panda.run_serial_cmd("cat /etc/passwd && sleep 2 && cat /etc/passwd && ls -la"))
        panda.run_monitor_cmd("end_record")
        panda.stop_run()
    panda.run()
else:
    print("recording exists. not remaking recording")

memory_mappings = {}

def address_in_malloc_map(cpu, address):
    asid = panda.current_asid(cpu)
    if asid in memory_mappings:
        maps = memory_mappings[asid]
        for m in maps:
            if m <= address and address <=m + maps[m]:
                return True
    return False


previous_size = None
def call_address_return(cpu, tb, h):
    asid = panda.current_asid(cpu)
    if asid in memory_mappings:
        mmaps = memory_mappings[asid]
    else:
        mmaps = {}
    ret = panda.arch.get_return_value(cpu)
    mmaps[ret] = previous_size
    memory_mappings[asid] = mmaps
    print(f"got malloc return with 0x{ret:x}")
    h.enabled = False

@panda.hook_symbol("libc", "__libc_malloc")
def hook_malloc(cpu,tb, h):
    size = panda.arch.get_arg(cpu,0)
    global previous_size
    previous_size = size
    print(f"got to malloc with size {size} {panda.get_process_name(cpu)} 0x{panda.current_asid(cpu):x} 0x{panda.current_pc(cpu):x}")
    ra = panda.arch.get_return_address(cpu)
    panda.hook(ra,enabled=True,kernel=False,asid=panda.current_asid(cpu))(call_address_return)

@panda.hook_symbol("libc", "__libc_calloc")
def hook_calloc(cpu,tb, h):
    size = panda.arch.get_arg(cpu,0)
    global previous_size
    previous_size = size
    print(f"got to calloc with size {size} {panda.get_process_name(cpu)} 0x{panda.current_asid(cpu):x} 0x{panda.current_pc(cpu):x}")
    ra = panda.arch.get_return_address(cpu)
    panda.hook(ra,enabled=True,kernel=False,asid=panda.current_asid(cpu))(call_address_return)

@panda.hook_symbol("libc", "__libc_realloc")
def hook_realloc(cpu,tb, h):
    old_ptr = panda.arch.get_arg(cpu,0)
    global previous_size
    previous_size = panda.arch.get_arg(cpu,1)
    asid = panda.current_asid(cpu)
    mmaps = memory_mappings[asid]
    if old_ptr != 0:
        if old_ptr in mmaps:
            del mmaps[old_ptr]
        else:
            print("missing old pointer")
    print(f"got to realloc with old pointer 0x{old_ptr:x} size {previous_size} {panda.get_process_name(cpu)} 0x{panda.current_asid(cpu):x} 0x{panda.current_pc(cpu):x}")
    ra = panda.arch.get_return_address(cpu)
    panda.hook(ra,enabled=True,kernel=False,asid=panda.current_asid(cpu))(call_address_return)

@panda.hook_symbol("libc", "__libc_free")
def hook_free(cpu,tb, h):
    ptr = panda.arch.get_arg(cpu,0)
    if ptr != 0:
        asid = panda.current_asid(cpu)
        mmaps = memory_mappings[asid]
        if ptr in mmaps:
            print(f"freeing previously found mmap at 0x{ptr:x} of size {mmaps[ptr]}")
            del mmaps[ptr]
        else:
            print(f"missed a malloc at 0x{ptr:x}")

@panda.hook_symbol("libc", "_Exit")
def hook_exit(cpu, tb, h):
    print(f"got to exit {panda.get_process_name(cpu)} 0x{panda.current_pc(cpu):x} 0x{panda.current_asid(cpu):x} {panda.in_kernel(cpu)}")
    asid = panda.current_asid(cpu)
    if asid in memory_mappings:
        print(f"Found #{len(memory_mappings[asid])} unfreed buffers")
        memory_mappings[asid] = {}

@panda.hook_symbol("libc", "write")
def hook_write(cpu, tb, h):
    arg1 = panda.arch.get_arg(cpu,1)
    try:
        trout = panda.read_str(cpu, arg1)
    except:
        trout = "?"

    print(f"{panda.get_process_name(cpu)} write \"{trout}\" 0x{arg1:x} {address_in_malloc_map(cpu, arg1)}")

panda.run_replay(recording_name)
