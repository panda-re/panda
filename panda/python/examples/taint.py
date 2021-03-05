from pandare import Panda
panda = Panda(generic='mips')

@panda.queue_blocking
def driver():
    panda.revert_sync('root')
    panda.run_serial_cmd("grep /etc/passwd root")
    panda.end_analysis()

@panda.ppp("syscalls2", "on_sys_read_return")
def read(cpu, tb, fd, buf, cnt):
    fname_raw = panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, fd)

    fname = panda.ffi.string(fname_raw)

    if fname == "/etc/passwd":
        for idx in range(cnt):
            panda.taint_label_ram(buf+idx)

@panda.ppp("taint2", "on_branch2")
def something(addr, pc):
    print("Tainted branch")

panda.run()

