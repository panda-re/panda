#!/usr/bin/python

import os
import sys
import subprocess as sp

thisdir = os.path.dirname(os.path.realpath(__file__))
td = os.path.realpath(thisdir + "/../..")
sys.path.append(td)

from ptest_utils import *


progress("Running test " + testname)
cmd = qemu + " -replay " + replayfile + " -os linux-32-lava32 -panda asidstory"

try:
    os.chdir(tmpoutdir)
    sp.check_call(cmd.split())
    progress ("Test %s succeeded" % testname)
except:
    progress ("Test %s failed to run " % testname)
    out = open(tmpoutfile, "w")
    out.write("Replay failed\n")

shutil.move("asidstory", tmpoutfile)


