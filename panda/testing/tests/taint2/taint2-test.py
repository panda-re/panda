#!/usr/bin/python

import os
import sys
import subprocess as sp
import tempfile

thisdir = os.path.dirname(os.path.realpath(__file__))
td = os.path.realpath(thisdir + "/../..")
sys.path.append(td)


from ptest_utils import *

# run taint_instr and tainted_branch on file_branch_taint program
testdir = testingscriptsdir + "/tests/taint2"
sp.check_call([pandascriptsdir + "/taint_debian.py", testdir + "/file_branch_taint", testdir + "/taint2.input"])

out = sp.check_output(["%s/plog_reader.py" % pandascriptsdir, "taint.plog"])

#out2 = [x for x in out.split('\n') if (not ('ptr' in x))]

f = open("%s/taint2.out" % tmpoutdir, "w")
f.write(out)

#for line in out2:
#    f.write(line + '\n')

f.close()

os.chdir(tmpoutdir)
shutil.move("taint2.out", tmpoutfile)
