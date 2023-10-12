from pandare import Panda
panda = Panda(generic="arm")
@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")
    for cmd in ["mkdir foo", "rmdir bar", "ls", "touch baz"]:
        panda.run_serial_cmd("sleep 2")
        print(panda.run_serial_cmd(cmd))
    panda.end_analysis()


# proc_start_linux can be a little touchy, might need to run this example a couple of times to see all the right output
# Do a different action on each of our commands.
@panda.ppp("proc_start_linux", "on_rec_auxv")
def inject_call(cpu, tb, auxv):
    procname = panda.get_process_name(cpu)
    if procname not in ["mkdir", "rmdir", "ls", "touch"]:
        return
    print(f"\n[python] started proc {procname}")
    if procname == "mkdir":
        print("[python] doing exit_group")
        exit_group(cpu)
        print("")
    elif procname == "rmdir":
        print("[python] doing exit_group2")
        exit_group2(cpu)
        print("")
    elif procname == "ls":
        print("[python] doing access")
        access(cpu)
        print("")
    elif procname == "touch":
        print("[python] doing access2")
        access2(cpu)
        print("")

# address of sys_access and exit_group found via experimentation
@panda.hook(0xc00c36b8)
def sys_access_hook(cpu, tb, h):
    name = panda.get_process_name(cpu)
    if name not in ["ls", "touch"]:
        return
    r0 = panda.arch.get_reg(cpu, "r0")
    if r0 not in [0x41424344, 0x44434241]:
        return
    print(f"[access] Got to access inside {name} with: r0={r0:#x}")

@panda.hook(0xc002e0f8)
def exit_group(cpu, tb, h):
    name = panda.get_process_name(cpu)
    if name not in ["mkdir", "rmdir"]:
        return
    r0 = panda.arch.get_reg(cpu, "r0")
    print(f"[exit_group] Got to exit_group inside {name} with: r0={r0:#x}")

# Inject an exit_group syscall using the raw plugin API
def exit_group(cpu):
    # need to cast the arguments to the syscall to types rust can handle, namely *const target_ulong
    raw_args = panda.ffi.new("target_ulong[]", [panda.ffi.cast("target_ulong",0xaabbccdd)])
    # call inject_syscall through sysinject, passing: 
    #     cpu 
    #     248 (syscall num for exit_group in arm)
    #     1 (since exit_group takes one argument)
    #     raw_args: the arguments to pass to the syscall, in this case 0xaa since it's a non-standard exit code
    panda.plugins["sysinject"].inject_syscall(cpu, 248, 1, raw_args)

# Inject an exit_group syscall using pypanda
def exit_group2(cpu):
    # Using this interface, you do not need to do the casting yourself
    # call inject_syscall through panda, passing:
    #     cpu: cpu state
    #     args: list of arguments, in this case just 0xab since it's a non-standard exit code
    panda.inject_syscall(cpu, 248, [0xddccbbaa])
    
fa = 1
# This hook will call sys_access through the base plugin interface
def access(cpu):
    # Need to gate the amount of times we call this hook because returning from it causes it to fire again.
    global fa
    if fa:
        fa = 0
    else:
        return
    raw_args = panda.ffi.new("target_ulong[]", [panda.ffi.cast("target_ulong", 0x41424344), panda.ffi.cast("target_ulong", 0x0)])
    # call sys_access, passing a pointer to the file name to access (the pointer can instead be used to page in memory containing that address)
    # as well as the mode
    panda.plugins["sysinject"].sys_access(cpu, raw_args)
    
fa2 = 1
def access2(cpu):
    global fa2
    if fa2:
        fa2 = 0
    else:
        return
    # basically the same as the previous hook, with fewer steps
    panda.sys_access(cpu, [0x44434241, 0x0])
    
panda.enable_precise_pc()
panda.disable_tb_chaining()
panda.run()