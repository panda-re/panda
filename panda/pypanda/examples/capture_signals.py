#!/usr/bin/env python3
'''
In this demo we use volatility to hook on group_send_sig_info. This is a kernel function
that handles notification of sent signals to processes. We intercept this to capture its
signal information.

Our blocking command is not a recording, but a snapshot that runs specific commands. In
particular, it runs:
        sleep 100 &
        kill -9 $!
The combination of the two starts a process sleep and then sends the signal 9 to it.

Once run our handle_signals function will be called and we can use volatility to parse 
its arguments. Doing so allows us to capture and print interesting informatoin about the
signal.
'''

from sys import argv
from panda import blocking, Panda

# No arguments, i386. Otherwise argument should be guest arch
arch = "x86_64"
image = "/home/luke/.panda/bionic-server-cloudimg-amd64.qcow2"
extra_args = "-nographic"
panda = Panda(arch=arch,qcow=image,extra_args=extra_args,expect_prompt=rb"root@ubuntu:.*",mem="1G")
panda.set_os_name("linux-64-ubuntu")

'''
handle_signals is a hoook on group_send_sig_info. It has the following sepecification
int group_send_sig_info(int sig, struct siginfo *info, struct task_struct *p) 
'''
def handle_signals(env, tb):
    regs = env.env_ptr.regs
    rdi, rsi, rdx, r10, r8, r9 = regs[7], regs[6], regs[2], regs[10], regs[8], regs[9]
    vmlinux = panda.get_volatility_symbols()
    signal = rdi
    info = vmlinux.object(object_type="siginfo", offset=rsi)
    p = vmlinux.object(object_type="task_struct", offset=rdx)
    sender = info._sifields._kill._pid
    receiver = p.pid
    print(f"process {sender} requested signal {signal} on process {receiver}")
    panda.end_analysis()
    return 0

@blocking
def run_cmd():
    global handle_signals
    panda.revert_sync("root")
    vmlinux = panda.get_volatility_symbols()
    send_sig_info = vmlinux.get_symbol(name="group_send_sig_info").address| 0xffff000000000000
    handle_signals = panda.hook(send_sig_info)(handle_signals)
    print("Sleep returning pid " + panda.run_serial_cmd("sleep 100 &"))
    panda.run_serial_cmd("kill -9 $!")

panda.queue_async(run_cmd)
panda.run()
