#!/usr/bin/env python3
'''
Run two commands in a guest and hook two kernel functions with python callbacks
Requires kernel symbol->address mappings which is generated with util/generate_kallsyms.py
'''

from sys import argv
from pandare import Panda, blocking
import time
import pickle

# Record some programs running in the guest
# for some programs, register python callbacks

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

# Generate with utils/example_generate_kallsyms.py
with open("i386_syms.pickle", "rb") as f:
    kallsyms = pickle.load(f)

# Run a command in the guest
@blocking
def my_runcmd():
    panda.revert_sync('root')
    panda.run_serial_cmd("cat /proc/self/environ")
    panda.run_serial_cmd("wget http://google.com")
    panda.stop_run()

panda.queue_async(my_runcmd)

# Register bkpt on sysfs_open_file
@panda.hook(kallsyms["system_call"])
def call_hook(env, tb):
    pc = panda.current_pc(env)
    print("System call at 0x{:x}: {}".format(pc, env.env_ptr.regs[0]))
    return False

@panda.hook(kallsyms["sys_access"])
def call_hook2(env, tb):
    pc = panda.current_pc(env)
    print("\t SYS_ACCESS (type=33)")
    return False

panda.run()
