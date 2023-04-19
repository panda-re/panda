#!/usr/bin/env python3
import sys
from sys import argv
from pandare import Panda
panda = Panda(generic="x86_64")

# Grabbed from malrec's listwins.py
import volatility.conf as conf
import volatility.registry as registry
registry.PluginImporter()
config = conf.ConfObject()
import volatility.commands as commands
import volatility.addrspace as addrspace
registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)
config.parse_options()

# Adapted from the `volatility.plugins.gui.windows` import
import volatility.plugins.linux.pslist as pslist

def try_pslist():
    global config
    print("Doing pslist maybe?")
    psl_plug = pslist.linux_pslist(config)
    for task in psl_plug.calculate():
        print(task)

def set_up(prof, sock):
    global config
    config.PROFILE = prof
    config.LOCATION = sock
    try_pslist()

@panda.queue_blocking
def run_cmd():
    global name, profile, path
    panda.revert_sync("root")
    # hacky because we need to sleep for a while but doing it as one sleep made panda sad (dead)
    panda.run_serial_cmd("sleep 10")
    #panda.run_serial_cmd("sleep 10")
    #panda.run_serial_cmd("sleep 10")
    #panda.run_serial_cmd("sleep 10")
    #panda.run_serial_cmd("sleep 10")
    print("[PANDA] " + panda.run_serial_cmd("lsb_release -a") + " [PANDA]\n")
    print("[PANDA] " + panda.run_serial_cmd("uname -a") + " [PANDA]\n")
    #set_up(profile, path)
    print("Done sleep, ending")
    panda.end_analysis()

#@panda.cb_asid_changed
def asidchange(cpu, old_asid, new_asid):
    #with open("outa","wb") as f:
    #    panda.memsavep(f)

    #panda.disable_callback("asidchange")
    return 0

path = "/home/rdm/pmem_sock3"
profile = "LinuxUbuntu_4_15_0-208-generic_profilex64"
dump = "/home/rdm/pmem.dump"

#print("Loading pmemaccess")
#panda.load_plugin("pmemaccess", args = {"path":path, "mode": 2})

panda.load_plugin("pmemaccess", args = {"path":path, "dump":dump, "mode": 1, "profile":profile, "command":"linux_pslist"})
#panda.load_plugin("pmemaccess", args = {"path":path, "mode": 1, "profile":profile, "command":"linux_pslist"})

panda.enable_precise_pc()
panda.disable_tb_chaining()
panda.run()
