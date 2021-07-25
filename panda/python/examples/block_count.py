#!/usr/bin/env python3
'''
block_count.py

Generate a test recording if one doesn't exist.
Use a before_block_exec callback when process is named bash
and count how many blocks we see execute, stop after 200

Run with: python3 block_count.py
'''

import os
from sys import argv
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

# Make sure we're always saving a new recording
recording_name = "test.recording"
if not os.path.isfile(recording_name+"-rr-nondet.log"): # Take new recording
    @panda.queue_blocking
    def record_nondet(): # Run a non-deterministic command at the root snapshot, then end .run()
        panda.record_cmd("date; cat /dev/urandom | head -n30 | md5sum", recording_name=recording_name)
        panda.stop_run()

    print("======== TAKE RECORDING ========")
    print("Please wait ~15 seconds for the guest to execute our commands\n")
    panda.run()
    print("======== END RECORDING ========")

blocks = 0
@panda.cb_before_block_exec(procname="bash")
def before_block_execute(cpustate, transblock):
    global blocks

    if blocks == 10:
        print("Finished with 10 BBs. Loading coverage plugin to start analysis")
        panda.load_plugin("coverage")

    if blocks == 50:
        print("Finished with 50 BBs. Ending coverage analysis")
        panda.unload_plugin("coverage")
        print("Unloaded coverage plugin")

    if blocks == 100:
        print("Finished with 100 BBs. Loading coverage plugin to start analysis")
        panda.load_plugin("coverage")

    if blocks == 150:
        print("Finished with 50 BBs. Ending coverage analysis")
        panda.unload_plugin("coverage")
        print("Unloaded coverage plugin")

    if blocks > 200:
        print("Saw 200 BBs. Stopping")
        panda.end_analysis() # Note we use end_analysis instead of stop run
                             # Which unregisters our callback while the guest
                             # is being stopped (which takes a few hundred BBs)
    blocks += 1

# Now run the replay
print("======== RUN REPLAY ========")
panda.run_replay(recording_name)
print("======== FINISH REPLAY ========")
