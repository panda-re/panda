from pandare import Panda
panda = Panda(generic='x86_64')

@panda.queue_blocking
def driver():
    panda.revert_sync('root')
    print(panda.run_serial_cmd("grep root /etc/passwd"))
    panda.end_analysis()

panda.require("osi")
panda.require("osi_linux")

def fd_to_fname(cpu, fd):
    proc = panda.plugins['osi'].get_current_process(cpu)
    procname = panda.ffi.string(proc.name) if proc != panda.ffi.NULL else "error"
    fname_ptr = panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
    fname = panda.ffi.string(fname_ptr) if fname_ptr != panda.ffi.NULL else "error"
    return fname

@panda.ppp("syscalls2", "on_sys_read_return")
def read(cpu, tb, fd, buf, cnt):
    fname = fd_to_fname(cpu, fd)
    print(f"read {fname}")

    if fname == "/etc/passwd":
        for idx in range(cnt):
            panda.taint_label_ram(buf+idx)

@panda.ppp("taint2", "on_branch2")
def something(addr, pc):
    print("Tainted branch")

panda.run()

