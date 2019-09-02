#!/usr/bin/env python3

from pypanda import *
from sys import argv
import subprocess
import os
import shlex
import threading


# Record some programs running in the guest
# for some programs, register python callbacks

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

# Python plugin- collect a set of unique basic blocks seen
seen_bbs = set()
@panda.callback.before_block_exec
def before_block_execute(env, tb):
    pc = panda.current_pc(env)
    global seen_bbs
    seen_bbs.add(pc)
    return True

# Run JQ from host machine. No plugins
@blocking
def record_jq():
    progress("Recording run of `jq`")
    guest_command = "/mnt/bin/jq . /mnt/inputs/fixed.json"
    copy_directory = "/tmp/jqB" # Host directory with file

    panda.record_cmd(guest_command, copy_directory, recording_name="jq")

# Run ls with c plugin loaded
@blocking
def record_ls():
    progress("Recording run of `ls` with c callback")

    # Load c plugin
    panda.load_plugin("coverage")

    panda.record_cmd("ls /", recording_name="ls")

    panda.unload_plugin("coverage")

# Run whoami with python plugin
@blocking
def record_whoami():
    progress("Recording run of `whoami` with callback")
    panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)

    panda.record_cmd("whoami", recording_name="whoami")

    global seen_bbs
    print("Saw a total of {} BBs while running ls".format(len(seen_bbs)))

    # By quitting here main thread can continue executing after panda.run
    # XXX: Need a better way to transfer control back to main thread - maybe via main_loop_wait callbacks?
    panda.run_monitor_cmd("quit")


# Handle is saved from on_init and then used later in our async thread to enable callbacks
handle = None

@panda.callback.init
def on_init(_handle):
    global handle
    handle = _handle
    return True

panda.load_python_plugin(on_init, "record_cmd_multiple")

# Queue up a sequence of commands to run outside the CPU loop
#panda.queue_async(record_jq) # Has paths specific to my host - AF
panda.queue_async(record_ls)
panda.queue_async(record_whoami)

panda.run()

# We get here after we quit via the monitor in the async thread
print("All done running commands")
