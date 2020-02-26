#!/usr/bin/env python3
'''
This file sets a breakpoint on every basic block. Every 10000 of them it
shows off the fact that it can determine both the program and the function
that you are in. It uses some fancy caching mechanisms that assume cr3
and cr3 + pc make a unique mapping (at least for duration of cache).

Run with python capture_library.py [qcow]
'''
from sys import argv
from volatility.framework.objects import utility, Pointer
from panda import blocking, Panda
import pdb, yaml, pickle, os
from functools import lru_cache

arch = "x86_64"
image = argv[1]
extra_args = "-nographic"
panda = Panda(arch=arch,qcow=image,extra_args=extra_args,expect_prompt=rb"root@ubuntu:.*",mem="1G")

elfmapping = None
symbolfile = "./bionic-server-cloudimg-amd64-userland-symbols.yml"

if os.path.exists(symbolfile+".pickle"):
    with open(symbolfile+".pickle","rb") as f:
        print("using pickle to load elfmapping")
        elfmapping = pickle.load(f)
    
if not elfmapping:
    if not os.path.exists(symbolfile):
        import urllib.request
        print('Beginning file download with urllib2...')
        url = 'http://panda-re.mit.edu/qcows/linux/ubuntu/1804/x86_64/bionic-server-cloudimg-amd64-userland-symbols.yml'
        urllib.request.urlretrieve(url, symbolfile)

    with open(symbolfile,"r") as f:
        print("opening userland symbols")
        elfmapping = yaml.load(f.read(),Loader=yaml.FullLoader)
        with open(symbolfile+".pickle", "wb") as p:
            print("pickling our symbols")
            pickle.dump(elfmapping,p)

mapping = {} # maps cr3 -> task_struct offsets

'''
Here we use volatility to make a mapping of cr3 to task_struct offsets in
memory. We use the init_task struct and iterate over the linked list of
task_structs. We use task.mm.pgd with a bit offset to find the correct
cr3 value.
'''
def update_process_mapping():
    global mapping
    print("calling update_process_mapping")
    mapping = {}
    vmlinux = panda.get_volatility_symbols()
    init_task= vmlinux.object_from_symbol("init_task")
    for task in init_task.tasks:
        if task and task.pid and task.mm:
            mapping[task.mm.pgd & 0xffffff] = task.vol["offset"]


'''
This function iterates over the vm_area_structs associated with each process.
It finds the correct one corresponding with the program counter. It then
iterates over the symbols for each library identified by the vm_area_struct
path member. From that point we look for the closest symbol which is not 
greater than our pc. The assumption made here is that functions are congiguous
memory regious between symbols. This might not be entirely true, but it's not
bad.
'''
def print_function_information(task,eip,vmlinux):
    rel_vma = None
    for vma in task.mm.get_mmap_iter(): 
        if vma.vm_start <= eip and vma.vm_end >= eip:
            rel_vma = vma
            break
    if rel_vma:
        path = rel_vma.get_name(vmlinux.context, task) 
        offset = eip-rel_vma.vm_start
        if path and path in elfmapping:
            m = elfmapping[path]
            best = None
            for symbol in m:
                if best is None:
                    best = symbol
                if m[symbol] < offset and m[symbol] > m[best]:
                    best = symbol
            return f"{utility.array_to_string(task.comm)} {path} {best} 0x{m[best]:x}"

'''
This function wants to find a task_struct for our cr3 and pass it to 
print_function_information. We have saved information in mapping and check for
the cr3 in previous results first before updating the mapping.
'''
@lru_cache(maxsize=1024, typed=False)
def location(cr3,eip):
    vmlinux = panda.get_volatility_symbols()
    cr3 = cr3 & 0xffffff
    if cr3 not in mapping:
        update_process_mapping()
    if cr3 in mapping:
        return print_function_information(vmlinux.object(object_type="task_struct", offset=mapping[cr3]),eip,vmlinux)


'''
Only real callback in this file. We just run every 10000 blocks. We pass
through our cr3 and program counter.
'''
blocks = 0
@panda.cb_before_block_exec()
def bbe(env,tb):
    global blocks
    if blocks >= 1000 and not panda.in_kernel(env):
        cr3 = env.env_ptr.cr[3]
        eip = env.env_ptr.eip
        print(location(cr3,eip))
        blocks = 0
    blocks += 1


'''
revert to root and run some commands to watch
'''
@blocking
def run_cmd():
    global hook_load_elf_binary,hook_open_exec,hook_kernel_read,hook_start_thread
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -r"))
    print(panda.run_serial_cmd("whoami"))
    print(panda.run_serial_cmd("lsmod"))
    print(panda.run_serial_cmd("rmmod kvm"))
    print(panda.run_serial_cmd("dmesg"))

panda.enable_memcb()
panda.queue_async(run_cmd)
panda.run()
