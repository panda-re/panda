#!/usr/bin/python

import os
import subprocess as sp
import sys
import re
import shutil 

thisdir = os.path.dirname(os.path.realpath(__file__))
td = os.path.realpath(thisdir + "/../..")
sys.path.append(td)

from ptest_utils import *

#cwd = os.getcwd()

#record_32bitlinux("%s/taint2 %s/taint2.input" % (cwd,cwd), 'taint2')
record_32bitlinux("%s/tests/taint2/file_branch_taint %s/tests/taint2/taint2.input" % (testingscriptsdir,testingscriptsdir), 'file_branch_taint')

