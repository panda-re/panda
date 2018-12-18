#!/usr/bin/python

# record and then replay the command '/usr/bin/file /bin/ls' 
# running on a 32-bit linux guest

import os
import sys
import shutil

thisdir = os.path.dirname(os.path.realpath(__file__))
td = os.path.realpath(thisdir + "/../..")
sys.path.append(td)

from ptest_utils import *


# this many rec / replay
num_tests = 100


num_pass_record = 0
num_pass_rr = 0

with open(tmpoutfile, "w") as tof:

    def both(msg, disp_fn):
        tof.write(msg + "\n")
        disp_fn(msg)

    for test in range(num_tests):
        try:
            record_debian("guest:/usr/bin/file guest:/bin/ls", "file", "i386")
            msg = "Recording for %s succeeded" % testname
            both(msg, progress)
            num_pass_record += 1
        except Exception as e:
            msg = "Recording for %s FAILED" % testname
            both(msg, error)
            continue

        try:
            run_test_debian("", "file", "i386", clear_tmpout=False)
            msg = "Replay for %s succeeded" % testname
            both(msg, progress)
            num_pass_rr += 1
        except Exception as e:
            msg = "Replay for %s FAILED" % testname
            both(msg, error)


    tof.write("%d pass record\n" % num_pass_record)
    tof.write("%d pass record+replay\n" % num_pass_rr)

    if num_pass_rr == num_tests:
        tof.write("RR test PASSED\n")
    else:
        tof.write("RR test FAILED\n")


# cleanup
shutil.rmtree(tmpoutdir + "/replays")
