#!/usr/bin/python

import os
import sys
import subprocess as sp

thisdir = os.path.dirname(os.path.realpath(__file__))
td = os.path.realpath(thisdir + "/../..")
sys.path.append(td)

from ptest_utils import *

run_test_32bitlinux("-panda general:first_instr=1 " \
                    + "-panda tstringsearch:only_first -panda stringsearch:name=" \
                    + search_string_file_pfx \
                    + " -panda tainted_instr:summary=y,num=2000")

os.chdir(tmpoutdir)
shutil.move("asidstory", tmpoutfile)
