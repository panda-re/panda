from pandare import Panda
panda = Panda(generic='arm')

@panda.queue_blocking
def driver():
    panda.revert_sync('root')
    print(panda.run_serial_cmd("grep root /etc/passwd"))
    panda.end_analysis()

panda.require("osi")
panda.require("osi_linux")

def fd_to_fname(env, fd):
    proc = panda.plugins['osi'].get_current_process(env)
    procname = panda.ffi.string(proc.name) if proc != panda.ffi.NULL else "error"
    fname_ptr = panda.plugins['osi_linux'].osi_linux_fd_to_filename(env, proc, fd)
    fname = panda.ffi.string(fname_ptr) if fname_ptr != panda.ffi.NULL else "error"
    return fname

tainted_branches = 0
@panda.ppp("syscalls2", "on_sys_read_return")
def read(cpu, tb, fd, buf, cnt):
    fname = fd_to_fname(cpu, fd)
    print(f"read {fname}")

    if fname == b"/etc/passwd":
        print(f"labeling /etc/passwd for buf")
        read_size = panda.arch.get_return_value(cpu)
        for idx in range(read_size):
            print
            taint_paddr = panda.virt_to_phys(cpu, buf + idx)  # Physical address
            if taint_paddr != -1:
                print(f"making taint on {taint_paddr:x}")
                panda.taint_label_ram(taint_paddr, idx)
            else:
                print("not doing taint because -1")

        @panda.ppp("taint2", "on_branch2")
        def something(addr, pc):
            #print("Tainted branch")
            global tainted_branches
            tainted_branches += 1

panda.libpanda.panda_enable_llvm()
try:
    panda.run()
except:
    pass
print(tainted_branches)