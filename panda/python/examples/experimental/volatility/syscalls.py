#!/usr/bin/env python3

from sys import argv
from pandare import Panda

# Record some programs running in the guest
# for some programs, register python callbacks

# Single arg of arch, defaults to i386
arch = "x86_64" if len(argv) <= 1 else argv[1]
extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4444,server,nowait  -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22 -cdrom /home/luke/workspace/qcows/instance-1-cidata.iso"
qcow = "/home/luke/workspace/qcows/instance-1.qcow2"
panda = Panda(arch=arch,qcow=qcow,extra_args=extra,mem="1G")
panda.set_os_name("linux-64-ubuntu")

panda.require("syscalls2")
cb_name = "on_sys_read_return"
cb_args = "CPUState *, target_ulong, uint32_t, uint64_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ffi.callback(f"void({cb_args})")
def on_sys_read_return(cpustate, pc, fd, buf, count):
	vmlinux = panda.get_volatility_symbols()
	import pdb
	pdb.set_trace()

panda.plugins["syscalls2"].__getattr__(f"ppp_add_cb_{cb_name}")(on_sys_read_return)

cb_name = "on_sys_read_enter"
cb_args = "CPUState *, target_ulong, uint32_t, uint64_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")
@ffi.callback(f"void({cb_args})")
def on_sys_read_enter(cpustate, pc, fd, buf, count):
#	vmlinux = panda.get_volatility_symbols()

panda.plugins["syscalls2"].__getattr__(f"ppp_add_cb_{cb_name}")(on_sys_read_enter)
panda.run()
