#!/usr/bin/env python3
import sys
from sys import argv
from pandare import Panda
panda = Panda(generic="x86_64")

#panda = Panda(arch='i386', qcow="/home/rdm/ubuntu.qcow2", mem="1G",
#        extra_args=f"-boot c \
#                     -nographic \
#                     -no-reboot \
#                     -serial\
#                     ")

#panda = Panda(arch='x86_64', qcow="/home/rdm/.panda/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow2", mem="1G",
#        extra_args=f"-nographic")

@panda.queue_blocking
def run_cmd():
    global name
    panda.revert_sync("root")
    #print(panda.run_serial_cmd("cat /proc/kallsyms | grep access"))
    panda.run_serial_cmd("sleep 50")
    #panda.run_serial_cmd("sleep 10")
    #panda.run_serial_cmd("sleep 10")
    #panda.run_serial_cmd("sleep 10")
    #panda.run_serial_cmd("sleep 10")
    print("Done sleep, ending")
    panda.end_analysis()

#@panda.cb_asid_changed
def asidchange(cpu, old_asid, new_asid):
    #with open("outa","wb") as f:
    #    panda.memsavep(f)

    #panda.disable_callback("asidchange")
    return 0

print("Loading pmemaccess")
#panda.load_plugin("pmemaccess", args = {"path":"/home/rdm/pmem_sock2", "mode": 2})

panda.load_plugin("pmemaccess", args = {"path":"/home/rdm/pmem_sock2", "mode": 1, "profile":"LinuxUbuntu18043x64", "command":"linux_pslist"})

panda.enable_precise_pc()
panda.disable_tb_chaining()
panda.run()
