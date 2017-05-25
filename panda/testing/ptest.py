#!/usr/bin/python

"""

NB: you need to set the PANDA_REGRESSION_DIR env variable for any
of this to work.  This is where all your regression testing will happen

You should be able to run the following

ptest.py init         (initializes testing, downloads some qcows)
ptest.py bless        (runs all enabled tests, blesses and saves outputs)
ptest.py test         (re-runs all enabled tests and checks output against blessed)

also, 

ptest.py              which is equiv to ptests.py test

each of these will print out lots of info about how the operation is
proceeding, and, at the end, provide a summary of which enabled tests
the operation succeeded for and which it failed for.  The very last
line will tell you if, overall, the operation succeeded.


Details.

./config.testing file contains list of tests that are currently
enabled.  each line in that file should be a directory under tests.
If you put '#' at the front of a line that will disable the test.



"""

import os
import sys
import argparse
import shutil
import subprocess as sp
import filecmp

if len(sys.argv) == 1:
    mode = 'test'
    all_targets = True
elif len(sys.argv) > 1:
    mode = sys.argv[1]
    all_targets = True
    targets = None
    if len(sys.argv) == 3:
        targets = sys.argv[2:]
        all_targets = (sys.argv[2] == 'all')

from ptest_utils import *

assert(mode in ['init', 'setup', 'bless', 'test'])

testsdir = testingscriptsdir+"/tests"

# make sure all enabled tests have min requirements
# of a setup and a test script
if debug: progress("checking min requirements")
for testname in enabled_tests:
    testdir = testsdir + "/" + testname
    dir_required(testdir)
    file_required(testdir + "/" + testname + "-setup.py")
    file_required(testdir + "/" + testname + "-test.py")


def setup(testname):
    progress ("Setup %s" % testname)
    try:
        os.chdir(testsdir)
        run("%s/%s/%s-setup.py" % (testsdir, testname, testname))
        progress ("Setup %s succeeded" % testname)
        return True
    except:
        error ("Setup %s failed" % testname)
        return False

def bless(testname):
    progress ("Bless %s" % testname)
    try:
        run("%s/%s/%s-test.py" % (testsdir, testname, testname))
        progress ("Replacing blessed file %s" % the_blessedfile(testname))
        shutil.move(the_tmpoutfile(testname), the_blessedfile(testname))
        progress ("Bless %s succeeded" % testname)
        return True
    except:
        error ("Bless %s failed" % testname)
        return False

def test(testname):
    progress ("Test %s" % testname)
    try:
        run("%s/%s/%s-test.py" % (testsdir, testname, testname))
        tof = the_tmpoutfile(testname)
        if not (file_exists(tof)):
            error ("tmp out for %s missing: %s" % (testname, tof))
            return False
        bf = the_blessedfile(testname)
        if not (file_exists(bf)):
            error ("blessed output for %s missing: %s" % (testname, bf))
            return False
        if filecmp.cmp(tof, bf):
            progress ("New output for %s agrees with blessed" % testname)        
            progress("Test %s succeeded" % testname)
            return True
        error("New output for %s DISAGREES with blessed" % testname)
        error("%s != %s" % (tof, bf))
        return False    
    except:
        error ("Test %s failed" % testname)
        return False

def do_all(do_fn):
    res = {}
    for testname in enabled_tests:
        res[testname] = do_fn(testname)
    return res

def run_mode(the_mode, do_fn):
    res = {}
    if all_targets:
        res = do_all(do_fn)
    else:
        for testname in targets:
            res[testname] = do_fn(testname)
    progress ("Summary results for %s" % the_mode)
    all_res = True
    i = 0
    for testname in res:
        if res[testname]:
            progress("  test %d %20s : %s succeeded" % (i, testname, the_mode))
        else:
            error("  test %d %20s : %s FAILED" % (i, testname, the_mode))
        all_res &= res[testname]
        i += 1
    if all_res:
        progress("All %s succeeded" % the_mode)
    else:
        error("XXX Some %s failed" % the_mode)

if mode == 'init':
    progress("Initializing panda regression test dir in " + pandaregressiondir)
    progress("Removing " + pandaregressiondir)
    shutil.rmtree(pandaregressiondir, ignore_errors=True)
    os.makedirs(pandaregressiondir)
    for dirname in ['qcows', 'replays', 'blessed', 'tmpout', 'misc']:
        os.mkdir(pandaregressiondir + "/" + dirname)
        for testname in enabled_tests:
            os.mkdir(the_dir(dirname, testname))
    os.chdir(pandaregressiondir + "/qcows")
    sp.check_call(["wget", "http://panda.moyix.net/~moyix/wheezy_panda2.qcow2", "-O", "wheezy_32bit.qcow2"])
    run_mode('setup', setup)

if mode == 'setup':
    run_mode(mode, setup)

if mode == 'bless':
    run_mode(mode, bless)

if mode == 'test':
    run_mode(mode, test)




