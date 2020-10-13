#!/usr/bin/env python3
from pandare import blocking, Panda
from os.path import isfile, expanduser
from requests import get

qcow = "https://people.debian.org/~aurel32/qemu/mips/debian_wheezy_mips_standard.qcow2"
vmlinux = "https://people.debian.org/~aurel32/qemu/mips/vmlinux-3.2.0-4-4kc-malta"
qcow_out = expanduser("~/.panda/debian_wheezy_mips_standard.qcow")
vmlinux_out = expanduser("~/.panda/vmlinux-3.2.0-4-4kc-malta")

if not isfile(qcow_out):
	open(qcow_out,'wb').write(requests.get(qcow).content)
if not isfile(vmlinux_out):
	open(vmlinux_out,'wb').write(requests.get(vmlinux).content)

panda = Panda(generic="mips",extra_args="-monitor telnet:127.0.0.1:4444,server,nowait")

replay = False
if replay:
	panda.run_replay("sample")
else:
	@blocking
	def q():
		panda.revert_sync("root")
#	panda.queue_async(q)
	panda.run()
