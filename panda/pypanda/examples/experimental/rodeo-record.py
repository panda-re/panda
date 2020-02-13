#!/usr/bin/env python3

from pypanda import *
from sys import argv
import subprocess
import os
import shlex
# Take a recording of a program running, then 
# replay and do a tainted_branch analysis on the recording

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch, extra_args = "")

name = None

"""
import glob
files = glob.glob("/nas/andrew/rode0day/clean/bins/14_jpegS-122_D1V-5D3V-lava-corpus-2018-09-20-17-15-17/inputs/*")
"""

# Record, then replay with plugins
@blocking
def record():
    global name
    input_name = "testorig-fuzzed-1028.jpg"

    guest_command = "/mnt/lava-install-public/bin/memdjpeg /mnt/inputs/" + input_name
    copy_directory = "/nas/andrew/rode0day/clean/bins/14_jpegS-122_D1V-5D3V-lava-corpus-2018-09-20-17-15-17"
    #panda.run_monitor_cmd("c")
    panda.record_cmd(guest_command, copy_directory, recording_name=name+".recording")
    progress("All done with recording")
    #panda.run_monitor_cmd("stop")
    panda.stop_run()

@blocking
def cont():
    print("CONT")
    print(panda.run_monitor_cmd("c"))
    print("CONT end")

def prepare_replay(name_):
    global name
    name = name_
    input_name = "testorig-fuzzed-1028.jpg"
    """
    panda.load_plugin("taint2", {"no_tp": True})
    panda.load_plugin("tainted_branch")
    panda.load_plugin("file_taint", args={"cache_process_details_on_basic_block": True, "pos": True,
                                          "filename": "/mnt/inputs/"+ input_name, "enable_taint_on_open": True})
    """
    panda.set_pandalog(name+".plog")

    progress("\nRun replay {} => {}".format(name+".plog", name+".recording"))
    panda.begin_replay(name+".recording") # XXX: when replay ends main thread will progress past panda.run()

def analyze():
    global name
    print("Done running panda. Now let's parse the plog")

    count = 0
    tainted_branch_pcs = set()
    with PLogReader(name+".plog") as plr:
        for i, m in enumerate(plr):
            if m.HasField('tainted_branch'):
                #print(m.pc, m.instr)
                tainted_branch_pcs.add(m.pc)
                count+=1
    print('\n]')

    print("Total taint branch count = {}".format(count))
    print("Unique PCs of tainted branches = {}".format(len(tainted_branch_pcs)))


names = ["jpeg1", "jpeg2"]

# XXX Can't do record,replay,record. But maybe can do record,record,replay,replay

# First take two recordings
for name in names:
    print("\nRECORD {}".format(name))
    panda.queue_async(record)
    panda.run()

# Then analyze the replays and build plogs
for name in names:
    #prepare_replay(name)
    panda.begin_replay(name+".recording") # XXX: when replay ends main thread will progress past panda.run()
    panda.run()

# Finally analyze the plogs
for name in names:
    print("ANALYZE {}".format(name))
    analyze()
