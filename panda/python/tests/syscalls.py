from panda import Panda, blocking, ffi
panda = Panda(generic="i386")

panda.load_plugin("syscalls2")

(execve_entered, execve_returned) = (False, False)

# Callback to run when we enter execve
@panda.ppp("syscalls2", "on_sys_execve_enter")
def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
    global execve_entered
    execve_entered = True

# Callback to run when we return from execve
@panda.ppp("syscalls2", "on_sys_execve_return")
def on_sys_execve_return(cpu, pc, fname_ptr, argv_ptr, envp):
    global execve_returned
    execve_returned = True

# In a separate thread, revert the test, run `whoami` and then end our analysis
@blocking
def guest_cmds():
    panda.revert_sync("root")
    print("Username is", panda.run_serial_cmd("whoami"))
    panda.end_analysis()

# Queue functions to run once guest starts, then start the guest
panda.queue_async(guest_cmds)
panda.run()

assert(execve_entered), "Syscalls never called execve enter"
#assert(execve_returned), "Syscalls never called execve return" # XXX: Known failure - see issue 392
