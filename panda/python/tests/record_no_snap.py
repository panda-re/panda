#!/usr/bin/env python3

from sys import argv
from pandare import Panda, blocking
from pandare.extras import ProcWriteCapture


# Take a recording without first reverting to a snapshot

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

rec_name = "test_ls"

@blocking
def record_no_revert():
    # Normally record_cmd will do the revert, but we want to modify the guest
    # after the snapshot and before the recording starts
    panda.revert_sync("root")
    panda.run_serial_cmd("mkdir /newdir")

    panda.record_cmd("ls /", recording_name=rec_name, snap_name=None)

    panda.end_analysis()


print("Queue up recording...")
panda.queue_async(record_no_revert)
panda.run()

print("Running replay")

# Use PWC to capture ls output and then we'll check host filesystem for the newdir string
pwc = ProcWriteCapture(panda, "ls", log_dir = "./pwc_log")
panda.run_replay(rec_name)

# Check pwc output for newdir
with open("./pwc_log/ls/_dev_ttyS0.stdout") as f:
    assert ("newdir" in f.read()), "Missing newdir in output"

