#!/usr/bin/python

import os
import sys
import subprocess as sp
import tempfile

thisdir = os.path.dirname(os.path.realpath(__file__))
td = os.path.realpath(thisdir + "/../..")
sys.path.append(td)

from ptest_utils import *

t = tempfile.NamedTemporaryFile() 
plogfile = t.name

run_test_32bitlinux("-pandalog %s -panda file_taint:filename=taint2.input,first_instr=100000,pos -panda tainted_branch " % plogfile)

out = sp.check_output(["%s/plog_reader.py" % pandascriptsdir, plogfile])

out2 = [x for x in out.split('\n') if (not ('ptr' in x))]

f = open("%s/taint2.out" % tmpoutdir, "w")
for line in out2:
    f.write(line + '\n')
f.close()

os.chdir(tmpoutdir)
shutil.move("taint2.out", tmpoutfile)
