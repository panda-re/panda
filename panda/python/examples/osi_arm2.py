#!/usr/bin/env python3
from panda import Panda, blocking, ffi
from panda.arm.helper import *
from panda.arm.helper import dump_state, registers

kernel = "linux-4.9.99/arch/arm/boot/zImage"
dtb    = "linux-4.9.99/arch/arm/boot/dts/vexpress-v2p-ca9.dtb"
append = "nokaslr root=/dev/mtdblock2 rw init=/bin/sh rootfstype=jffs2 \
       earlyprintk=serial,ttyAMA0 console=ttyAMA0"

panda = Panda("arm", mem="256", extra_args=
            ["-M", "vexpress-a9", "-kernel", kernel, "-dtb", dtb, "-append", append, "-nographic",
            "-drive", "if=none,file=fs1.jffs2,id=vda,format=raw",
            "-device", "virtio-blk-device,drive=vda",
            ])

panda.set_os_name("linux-64-ubuntu:4.9.99") # XXX: not really ubuntu
panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
panda.load_plugin("syscalls2")

panda.load_plugin("osi", {"disable-autoload": True})
panda.load_plugin("osi_linux", {'kconf_file':'/home/andrew/git/panda/build/kinfo-4.9.99.conf', 'kconf_group': 'ubuntu:4.9.99:64'})


# Log process name before each MMIO write
"""
last_proc_name = None
@panda.cb_mmio_before_write(enabled=False)
def test_cb(cpu, *args):
    # print if there's a new proc name

    global last_proc_name
    #load_cached(cpu)
    proc = panda.plugins['osi'].get_current_process(cpu)
    if proc != ffi.NULL and ffi.string(proc.name) != last_proc_name:
        last_proc_name = ffi.string(proc.name)
        print("MMIO write from:", last_proc_name)
"""

@panda.ppp("syscalls2", "on_sys_execve_enter")
def test_execve_enter(cpu, pc, *args):
    proc = panda.plugins['osi'].get_current_process(cpu)
    if proc == ffi.NULL:
        print(f"OSI failure in execve_enter at pc=0x{panda.current_pc(cpu):x}, kernel=", panda.in_kernel(cpu))
        panda.enable_callback("next_bb_break")
    else:
        print(f"OSI success in execve_enter, process {ffi.string(proc.name) if proc.name != ffi.NULL else 'null'}")


#@panda.ppp("syscalls2", "on_sys_close_enter")
def test_close(cpu, pc, fd):
    '''
    When we see a close, translate FD to filename using OSI
    '''
    proc = panda.plugins['osi'].get_current_process(cpu)
    if proc == ffi.NULL:
        print(f"CLOSE_ENTER had OSI failure, pc=0x{panda.current_pc(cpu):x} kernel=", panda.in_kernel(cpu))
        panda.enable_callback("next_bb_break")
    else:
        print(f"Process {ffi.string(proc.name)} has fd {fd} backed by:", ffi.string(panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)))

def _print_procs(procs, cur_pid, cur_depth=0):
    '''
    Print the current process at the given depth. Recurse for each child with depth + 1
    '''

    # print name
    print(" | "*cur_depth + str(cur_pid) + "  " + procs[cur_pid][0])
    for child_pid, (child_name, parent_pid) in procs.items():
        if parent_pid == cur_pid and child_pid != cur_pid:
            _print_procs(procs, child_pid, cur_depth+1)

def pstree(cpu):
    print("Process tree:")
    procs = {} #pid: (name, parent_pid)

    for proc in panda.get_processes(cpu):
        assert(proc != ffi.NULL)
        assert(proc.pid not in procs)
        procs[proc.pid] = (ffi.string(proc.name).decode('utf8'), proc.ppid)

    if len(procs):
        #_print_procs(procs, 0)
        print("Success, found procs")
    else:
        print("Error getting processes")


@panda.cb_before_block_exec_invalidate_opt(enabled=False)
def next_bb_break(cpu, tb):
    '''
    Fallback. If OSI failed, try again in the next block
    '''
    print(f"---------- FALLBACK @ next block ----------")
    pstree(cpu)

    panda.disable_callback("next_bb_break")
    task_thread_info = cpu.env_ptr.banked_r13[1] & 0xffffe000
    print(f"(struct thread_info*) 0x{task_thread_info:x}")
    print(f"\tkernel=", panda.in_kernel(cpu))

    proc = panda.plugins['osi'].get_current_process(cpu)
    if proc != ffi.NULL:
        fd1 = panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, 1)
        fd_str = ffi.string(fd1) if fd1 != ffi.NULL else "unknown"
        print(f"Process {ffi.string(proc.name) if proc.name != ffi.NULL else 'unknown'} fd1: {fd_str}\n")
        return False

    #print("BREAKPOINT")
    #panda.set_breakpoint(cpu, panda.current_pc(cpu))
    print("\n")
    #return True
    return False

# Start guest execution
panda.run()
