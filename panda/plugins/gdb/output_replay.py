#!/usr/bin/env python3

from sys import argv
from pandare import blocking, Panda, ffi

# No arguments, i386. Otherwise argument should be guest arch
generic_type = argv[1] if len(argv) > 1 else "x86_64"
panda = Panda(generic=generic_type)

#@blocking
#def run_cmd():
    # First revert to root snapshot, then type a command via serial
    #panda.revert_sync("root")

#    panda.end_analysis()

#panda.queue_async(run_cmd)

@panda.ppp('syscalls2', 'on_sys_write_enter')
def proc_write_capture_on_sys_write_enter(cpu, pc, fd, buf, cnt):
    curr_proc = panda.plugins['osi'].get_current_process(cpu)
    file_name_ptr = panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, curr_proc, fd)
    if ffi.string(file_name_ptr).decode() == "/dev/ttyS0":
        print(panda.virtual_memory_read(cpu, buf, cnt).decode(), end="")

print(panda.run_replay("catmaps"))
#panda.run()
