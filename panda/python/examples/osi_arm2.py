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

# At first execve, enable on_enter_svc callback
@panda.ppp("syscalls2", "on_sys_execve_enter")
def first_syscall(cpu, pc, fname_ptr, argv_ptr, envp):
    #TODO: change to run on first syscall, not just execve
    panda.enable_callback('asid_changed')
    #panda.disable_callback("first_syscall") # XXX: can't disable because it's a PPP fn

task_thread_info = None
@panda.cb_on_enter_svc(enabled=False)
def asid_changed(cpu):
    global task_thread_info

    sp = cpu.env_ptr.regs[R_SP]
    task_thread_info = sp & 0xffffe000
    print(hex(task_thread_info))

    try:
        # task_struct is 0xC into the struct
        task_ptr = panda.virtual_memory_read(cpu, task_thread_info+0xC,
                                                4, fmt='int')
    except Exception as e:
        print(f"Fail to read task ptr from task_thread_info at 0x{task_thread_info:x}")
        return
    if task_ptr:
        print(f"Task ptr: 0x{task_ptr:x}")

# Start guest execution
panda.run()
