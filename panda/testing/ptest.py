#!/usr/bin/python
#
"""NB: you need to set the PANDA_REGRESSION_DIR env variable for any
of this to work


./config.testing file contains list of tests that are currently enabled.
each line in that file should be a directory under tests.
for example, say we have the following

 % cat ./config.testing
   asidstory1
   stringsearch1
   ...

Then that means the following directories should exist

 % ls -1 tests
   asidstory1
   stringsearch1 
   ...

Each of those subdirectories should contain two python scripts.

 % ls -1 asidstory1
   asidstory1-setup.py    [for set up -- creating a replay, downloading a qcow, etc
   asi


USAGE:

ptest.py init 

    will delete and recreate the regression directory.  Destructive!
    will also run all setup scripts for enabled tests


ptest.py setup asidstory1

    runs setup just for this test

ptest.py bless all
 
    runs all of the tests and if they all succeed, saves blessed
    outputs for later comparison

ptest.py bless asidstory1

    just runs test for asidstory1 and blesses output

ptest.py test all

    runs all tests and checks against blessed output

ptesty.py test asdistory1

    runs asidstory1 test and checks it


"""

import os
import sys
import argparse
import shutil
import subprocess as sp
import filecmp

if len(sys.argv) == 3:
    targets = sys.argv[2:]
    all_targets = (sys.argv[2] == 'all')
else:
    all_targets = True
    targets = None

from ptest_utils import *

mode = sys.argv[1]

assert(mode in ['init', 'setup', 'bless', 'test'])

testsdir = testingscriptsdir+"/tests"

# make sure all enabled tests have min requirements
# of a setup and a test script
progress("checking min requirements")
for testname in enabled_tests:
    testdir = testsdir + "/" + testname
    dir_required(testdir)
    file_required(testdir + "/" + testname + "-setup.py")
    file_required(testdir + "/" + testname + "-test.py")


def setup(testname):
    progress ("Setup %s" % testname)
    try:
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
    for testname in res:
        if res[testname]:
            progress("  test %s : %s succeeded" % (testname, the_mode))
        else:
            error("  test %s : %s FAILED" % (testname, the_mode))
        all_res &= res[testname]
    if all_res:
        progress("All %s succeeded" % the_mode)
    else:
        error("Some %s failed" % the_mode)

if mode == 'init':
    progress("Initializing panda regression test dir in " + pandaregressiondir)
    shutil.rmtree(pandaregressiondir, ignore_errors=True)
    os.makedirs(pandaregressiondir)
    for dirname in ['qcows', 'replays', 'blessed', 'tmpout', 'misc']:
        os.mkdir(pandaregressiondir + "/" + dirname)
        for testname in enabled_tests:
            os.mkdir(the_dir(dirname, testname))
    run_mode('setup', setup)

if mode == 'setup':
    run_mode(mode, setup)

if mode == 'bless':
    run_mode(mode, bless)

if mode == 'test':
    run_mode(mode, test)




