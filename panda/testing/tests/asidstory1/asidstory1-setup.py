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

# create the replay to use for reference / test
cmd = pandascriptsdir + "/run_on_32bitlinux.py guest:/bin/netstat -a"
os.chdir(pandaregressiondir)
print cmd
sp.check_call(cmd.split())

base = pandaregressiondir + "/replays/netstat/netstat-rr-"
replaysdir = pandaregressiondir + "/replays/" + testname
if not (os.path.exists(replaysdir) and os.path.isdir(replaysdir)):
    os.makedirs(replaysdir)

newbase = replaysdir + "/" + testname + "-rr-"

moveit(base, newbase, "nondet.log")
moveit(base, newbase, "snp")

# cruft
shutil.rmtree(pandaregressiondir + "/replays/netstat")

