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

def both(msg, disp_fn):
    tof.write(msg + "\n")
    disp_fn(msg)

tof = open(tmpoutfile, "w")
try:
    record_debian("guest:/usr/bin/file guest:/bin/ls", "file", "i386")
    msg = "Create recording for %s succeeded" % testname
    both(msg, progress)
except Exception as e:
    msg = "Create recording for %s FAILED" % testname
    both(msg, error)
    tof.close()
    raise e

try:
    run_test_debian("", "file", "i386")
    msg = "Replay for %s succeeded" % testname
    both(msg, progress)
    tof.close()
except Exception as e:
    msg = "Replay for %s FAILED" % testname
    both(msg, error)
    tof.close()
    raise e
