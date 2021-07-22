#!/usr/bin/env python3

from pandare import Panda
panda = Panda(generic="i386")

panda.load_plugin("syscalls2")

(open_entered, open_returned) = (False, False)
run_count = 0

# Run on any syscall, but disable after the very first one
# to test disablging PPP callbacks
@panda.ppp("syscalls2", "on_all_sys_enter")
def any_syscall(cpu, pc, callno):
    global run_count
    run_count += 1
    panda.disable_ppp("any_syscall")

# Callback to run when we enter an open
@panda.ppp("syscalls2", "on_sys_open_enter")
def on_sys_open_enter(cpu, pc, fname_ptr, flags, mode):
    global open_entered
    open_entered = True

# Callback to run when we return from open
@panda.ppp("syscalls2", "on_sys_open_return")
def on_sys_open_return(cpu, pc, fname_ptr, flags, mode):
    global open_returned
    open_returned = True

# Qeueu function to run a separate thread which reverts the test, run `whoami` and then end our analysis
@panda.queue_blocking
def guest_cmds():
    panda.revert_sync("root")
    print("Username is", panda.run_serial_cmd("whoami"))
    panda.end_analysis()

# Start the guest (and launch queued functions in another thread)
panda.run()

assert(open_entered), "Syscalls never called open enter"
assert(run_count == 1), f"PPP callback didn't run once, it ran {run_count} times"
assert(open_returned), "Syscalls never called open return"
