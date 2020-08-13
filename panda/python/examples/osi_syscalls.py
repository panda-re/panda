#!/usr/bin/env python3
from panda import Panda, blocking, ffi

panda = Panda(generic="x86_64")

panda.load_plugin("syscalls2")
panda.load_plugin("osi")

@panda.ppp("syscalls2", "on_sys_read_return")
def on_sys_read_return(cpu, pc, fd, buf, count):
    proc = panda.plugins['osi'].get_current_process(cpu)
    procname = ffi.string(proc.name) if proc != ffi.NULL else "error"
    fname_ptr = panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
    fname = ffi.string(fname_ptr) if fname_ptr != ffi.NULL else "error"
    print(f"[PANDA] {procname} read from {fname}")


@blocking
def start():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("cat /etc/passwd"))
    panda.end_analysis()

panda.queue_async(start)
panda.run()
