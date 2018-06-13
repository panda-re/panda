#!/usr/bin/python

import os
import sys
import subprocess as sp

thisdir = os.path.dirname(os.path.realpath(__file__))
td = os.path.realpath(thisdir + "/../..")
sys.path.append(td)

from ptest_utils import *

run_test_debian("-panda asidstory -os linux-32-lava32 ", 'netstat',"i386")


shutil.copyfile(tmpoutdir + "/asidstory", tmpoutfile)
