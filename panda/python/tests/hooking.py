#!/usr/bin/env python3
'''
XXX: Broken - our kernels don't have the system_call and sys_access functions in their System.map

1) Start guest and identify kernel symbol->address mappings. End execution
2) Restart guest with two kernel functions hooked.
3) Once both hooks are triggered, end analysis

Both kernel functions should run in the guest and (therefore) both hook functions should be called

This test currently is failing 1/2 the time, probably due to some bug in the hooks plugin?
'''

from sys import argv
from pandare import Panda
import time
import pickle

arch = "i386"
panda = Panda(generic=arch)

# First run - Just get symbols
# Extract kernel symbols and populate dictionary
kallsyms = {}
@panda.queue_blocking
def extract_kallsyms():
    global kallsyms
    # First revert to root snapshot, then type a command via serial
    panda.revert_sync("root")
    syms = panda.run_serial_cmd("grep -h 'system_call\\|sys_access' /boot/System.map*")
    print(syms)

    for line in syms.splitlines():
        line = line.strip()
        addr = int(line.split(" ")[0], 16)
        name = line.split(" ")[-1]
        kallsyms[name] = addr
    panda.end_analysis()

print("\nStarting guest to extract kernel symbols. This will take a moment...")
panda.run()
assert(len(kallsyms) > 100), f"Error - Only identified {len(kallsyms)} symbols"

print(f"Identified {len(kallsyms)} kernel symbols")
print(f"\tsystem_call   at 0x{kallsyms['system_call']:x}")
print(f"\tsystem_access at 0x{kallsyms['sys_access']:x}")

# Hook system_call and sys_access
# Both should run in the replay
syscall_ran_ctr   = 0
sysaccess_ran_ctr = 0
# Whenever we syscal(33), set need_sysaccess
# whenever we run sys_access, clear it.
# If need_sysaccess is ever set in a syscall
# something went wrong
need_sysaccess = False

@panda.hook_single_insn("call_hook", kallsyms["system_call"], kernel=True)
def call_hook(env, tb):
    pc = panda.current_pc(env)
    syscall_num = env.env_ptr.regs[0]
    #print(f"System call at 0x{pc:x}: {syscall_num}")

    # Store the syscall number
    global syscall_ran_ctr, need_sysaccess
    syscall_ran_ctr += 1
    assert(not need_sysaccess), "Sys_access hook didn't run"
    if syscall_num == 33:
        need_sysaccess = True

    return False

@panda.hook("call_hook2", kallsyms["sys_access"], kernel=True)
def call_hook2(env, tb):
    pc = panda.current_pc(env)
    global sysaccess_ran_ctr, need_sysaccess
    sysaccess_ran_ctr += 1
    need_sysaccess = False

    return False

# Run a command in the guest which should cause hooks to trigger
@panda.queue_blocking
def my_runcmd():
    panda.revert_sync('root')
    panda.run_serial_cmd("cat /proc/self/environ")
    panda.run_serial_cmd("wget http://example.com")
    panda.stop_run()

print("Running guest with two hooks")
panda.run()

assert(syscall_ran_ctr   > 0), "System_call hook never ran"
assert(sysaccess_ran_ctr > 0), "Sys_access hook never ran"
assert(not need_sysaccess),    "Sys_access failed to run after last syscall"

print(f"Test finished successfully. Syscall hook ran {syscall_ran_ctr} times")
print(f"\tand sysaccess hook ran {sysaccess_ran_ctr} times.")
