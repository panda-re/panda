#!/usr/bin/python

import os
import sys
import subprocess as sp

thisdir = os.path.dirname(os.path.realpath(__file__))
td = os.path.realpath(thisdir + "/../..")
sys.path.append(td)

from ptest_utils import *

run_test_32bitlinux("-panda asidstory")

os.chdir(tmpoutdir)
shutil.move("asidstory", tmpoutfile)

