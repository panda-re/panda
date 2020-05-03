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

panda.set_os_name("linux-32-debian:4.9.99")
panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
panda.load_plugin("syscalls2")

# At first execve (boot is finished), enable the BBE callback
first_execve = True
@panda.ppp("syscalls2", "on_sys_execve_enter")
def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
    global first_execve
    if first_execve:
        first_execve = False
        panda.enable_callback('bbe')

task_thread_info = None
last = None

@panda.cb_before_block_exec(enabled=False)
def bbe(cpu, tb):
    global task_thread_info, last

    if not task_thread_info and panda.in_kernel(cpu): # Need to find task_thread_info
        # Grab and mask SP to get the restult of current_thread_info() in info
        sp = cpu.env_ptr.regs[R_SP]
        task_thread_info = sp & 0xffffe000

    if task_thread_info:
        try:
            # task_struct is 0xC into the struct
            task_ptr = panda.virtual_memory_read(cpu, task_thread_info+0xC, 4, fmt='int')
        except Exception as e:
            #print(f"\tFailed to read task_ptr struct: {e}. Recomputing next time we enter kernel")
            task_thread_info = None # Need to redetermine?
            return

        if task_ptr != last:
            print(f"Task ptr: 0x{task_ptr:x}")
            last = task_ptr



# Start guest execution
panda.run()
