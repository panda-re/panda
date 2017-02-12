#!/usr/bin/python

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
    record_32bitlinux("guest:/usr/bin/file guest:/bin/ls", "file")
    msg = "Create recording for %s succeeded" % testname
    both(msg, progress)
except Exception as e:
    msg = "Create recording for %s FAILED" % testname
    both(msg, error)
    tof.close()
    raise e

try:
    run_test_32bitlinux("")
    msg = "Replay for %s succeeded" % testname
    both(msg, progress)
    tof.close()
except Exception as e:
    msg = "Replay for %s FAILED" % testname
    both(msg, error)
    tof.close()
    raise e
