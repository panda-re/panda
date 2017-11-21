#!/usr/bin/python

import os
import sys
import subprocess as sp
import random
import struct

thisdir = os.path.dirname(os.path.realpath(__file__))
td = os.path.realpath(thisdir + "/../..")
sys.path.append(td)

from ptest_utils import *
# This test doesn't write any output files, just checks that replay works for each snip

# we try this many scissor snips for each of the replays we created in setup
# note, each snip is random start / end
num_tests = 100

num_pass = 0
num_fail = 0

# get number of instructions in file 
for binary in ["netstat", "find"]:
    # ew -- ray this is grossssss
    with open(replaydir+"/%s-rr-nondet.log" % binary, 'rb') as f:
        num_instrs = struct.unpack("<Q", f.read()[:8])
        num_instrs = num_instrs[0]

    random.seed()
    for i in range(num_tests):
        start_pos = random.randint(0, num_instrs)
        end_pos = random.randint(start_pos, num_instrs)

        # Create slice
        run_test_debian("-panda scissors:name=" + replaydir + "/%s_reduced,start=%d,end=%d" % (binary, start_pos, end_pos), binary,"i386")

        # Attempt to replay slice. 
        try:
            run_test_debian("", "%s_reduced" % binary, "i386")
            msg = "Replay for %s (snipping %d to %d) succeeded" % (testname, start_pos, end_pos)
            progress(msg)
            num_pass += 1
        except Exception as e:
            msg = "Replay for %s (snipping %d to %d) FAILED" % (testname, start_pos, end_pos)
            error(msg)
            error(e)
            num_fail += 1

os.chdir(tmpoutdir)
with open(tmpoutfile, "w") as f:
    f.write("scissors-test results: %d pass %d fail\n" % (num_pass, num_fail))
    if num_pass == num_tests:
        f.write("Scissors PASS\n")
    else:
        f.write("Scissors FAIL\n")

