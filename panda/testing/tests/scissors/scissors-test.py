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

# get number of instructions in file 
with open(replaydir+"/find-rr-nondet.log", 'rb') as f:
    num_instrs = struct.unpack("<Q", f.read()[:8])
    num_instrs = num_instrs[0]

random.seed(0)
for i in range(10):
    start_pos = random.randint(0, num_instrs)
    end_pos = random.randint(start_pos, num_instrs)

    # Create slice
    run_test_debian("-panda scissors:name=" + replaydir + "/find_reduced,start=%d,end=%d" % (start_pos, end_pos), 'find',"i386")

    # Attempt to replay slice. 
    try:
        run_test_debian("", "find_reduced", "i386")
        msg = "Replay for %s (snipping %d to %d) succeeded" % (testname, start_pos, end_pos)
        progress(msg)
    except Exception as e:
        msg = "Replay for %s (snipping %d to %d) FAILED" % (testname, start_pos, end_pos)
        error(msg)
        raise e
