#!/usr/bin/env python3
'''
osi_syscalls.py

This example shows PPP calls through syscalls2.

Run with: python3 osi_syscalls.py
'''
from pandare import Panda
from sys import argv

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.ppp("syscalls2", "on_sys_read_return")
def on_sys_read_return(cpu, pc, fd, buf, count):
    proc = panda.plugins['osi'].get_current_process(cpu)
    procname = panda.ffi.string(proc.name) if proc != panda.ffi.NULL else "error"
    fname_ptr = panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
    fname = panda.ffi.string(fname_ptr) if fname_ptr != panda.ffi.NULL else "error"
    rc = panda.plugins['syscalls2'].get_syscall_retval(cpu)
    print(f"[PANDA] {procname} read {rc} bytes from {fname}")

@panda.ppp("syscalls2", "on_sys_execve_enter")
def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
    # Log commands and arguments passed to execve unless in kernel
    if panda.in_kernel(cpu):
        return
    try:
        fname = panda.read_str(cpu, fname_ptr)
        argv_ptrlist = panda.virtual_memory_read(cpu, argv_ptr, 80, fmt='ptrlist')
    except ValueError: return
    argv = []
    for ptr in argv_ptrlist:
        if ptr == 0: break
        try:
            argv.append(panda.read_str(cpu, ptr))
        except ValueError:
            argv.append(f"(error: 0x{ptr:x})")

    print(get_calltree(cpu) + " => " + ' '.join(argv))

def get_calltree(cpu):
    # Print the calltree to the current process
    proc = panda.plugins['osi'].get_current_process(cpu)
    if proc == panda.ffi.NULL:
        print("Error determining current process")
        return
    procs = panda.get_processes_dict(cpu)

    chain = [{'name': panda.ffi.string(proc.name).decode('utf8', 'ignore'),
              'pid': proc.pid, 'parent_pid': proc.ppid}]
    while chain[-1]['pid'] > 1 and chain[-1]['parent_pid'] in procs.keys():
        chain.append(procs[chain[-1]['parent_pid']])
    return " -> ".join(f"{item['name']} ({item['pid']})" for item in chain[::-1])


@panda.queue_blocking
def start():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("cat /etc/passwd"))
    panda.end_analysis()

panda.run()
