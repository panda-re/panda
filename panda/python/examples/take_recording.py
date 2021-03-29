#!/usr/bin/env python3

from sys import argv
from pandare import Panda, blocking

# Record some programs running in the guest
# for some programs, register python callbacks

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

# Python plugin- collect a set of unique basic blocks seen
seen_bbs = set()
@panda.cb_before_block_exec(enabled=False)
def bbe(cpu, tb):
    pc = panda.current_pc(cpu)
    global seen_bbs
    seen_bbs.add(pc)

# Run ls with c plugin loaded
@panda.queue_blocking
def record_ls():
    print("Recording run of `ls` with C callback")

    # Load c plugin
    panda.require("coverage")
    panda.record_cmd("ls /", recording_name="ls")
    panda.unload_plugin("coverage")
    panda.stop_run() # Here we use stop_run instead of end_analysis because we want the bbe
                     # callback to continue to exist for subsequent panda.run() calls

print("Queue up recording of `ls` and run with C-coverage plugin")
panda.run()

# Run whoami with python plugin
@panda.queue_blocking
def record_whoami():
    print("Recording run of `whoami` with python callback")
    panda.enable_callback("bbe")

    panda.record_cmd("whoami", recording_name="whoami")

    global seen_bbs
    print("Saw a total of {} BBs while running ls".format(len(seen_bbs)))
    panda.end_analysis()


print("Queue up recording of `whoami` and run with python plugin")
panda.run()

# We get here after we quit via the monitor in the async thread
print("All done running commands")
