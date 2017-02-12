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
    run("%s/%s/%s-setup.py" % (testsdir, testname, testname))

def setup_all():
    for testname in enabled_tests:
        setup(testname)

if mode == 'init':
    progress("Initializing panda regression test dir in " + pandaregressiondir)
    shutil.rmtree(pandaregressiondir, ignore_errors=True)
    os.makedirs(pandaregressiondir)
    os.mkdir(pandaregressiondir + "/qcows")
    os.mkdir(pandaregressiondir + "/replays")
    os.mkdir(pandaregressiondir + "/blessed")
    os.mkdir(pandaregressiondir + "/tmpout")
    for testname in enabled_tests:
        os.mkdir(the_dir("replays", testname))
        os.mkdir(the_dir("blessed", testname))
        os.mkdir(the_dir("tmpout", testname))
    setup_all()
    sys.exit(0)

if mode == 'setup':
    if all_targets:
        setup_all()
    else:
        for testname in targets:
            setup(testname)

def bless(testname):
    try:
        run("%s/%s/%s-test.py" % (testsdir, testname, testname))
        shutil.move(the_tmpoutfile(testname), the_blessedfile(testname))
        progress ("Replacing blessed file %s" % the_blessedfile(testname))
        return True
    except:
        progress ("Blessing of %s failed" % testname)
        return False

def bless_all():
    blessed = {}
    for testname in enabled_tests:
        blessed[testname] = bless(testname)
    return blessed

if mode == 'bless':
    blessed = {}
    if all_targets:
        blessed = bless_all()
    else:
        for testname in targets:
            blessed[testname] = bless(testname)
    progress("Blessing summary:")
    all_blessed = True
    for testname in blessed:
        if blessed[testname]:
            progress ("  test %s : blessed" % testname)
        else:
            progress ("  test %s : NOT blessed" % testname)
        all_blessed &= blessed[testname]
    if all_blessed:
        progress("Every enabled test has been blessed")
    else:
        progress ("XXX Not all enabeld tests were blessed")

def test(testname):
    run("%s/%s/%s-test.py" % (testsdir, testname, testname))
    tof = the_tmpoutfile(testname)
    if not (file_exists(tof)):
        progress ("tmp out %s doesnt exist" % tof)
        sys.exit(1)
    bf = the_blessedfile(testname)
    if not (file_exists(bf)):
        progress ("blessed %s doesnt exist" % bf)
        sys.exit(1)            
    if filecmp.cmp(tof, bf):
        progress ("New output agrees with blessed")        
        return True
    return False

def test_all():
    succeeded = {}
    for testname in enabled_tests:
        succeeded[testname] = test(testname)
    return succeeded

if mode == 'test':
    succeeded = {}
    if all_targets:
        succeeded = test_all()
    else:
        for testname in targets:
            testd[testname] = test(testname)
    progress ("Testing summary:")
    all_succeeded = True
    for testname in succeeded:
        if succeeded[testname]:
            progress ("  test %s : succeeded" % testname)
        else:
            progress ("  test %s : FAILED" % testname)
        all_succeeded &= succeeded[testname]
    if all_succeeded:
        progress("Every enabled test agreed with blessed")
    else:
        progress ("XXX Not all enabeld tests agreed with blessed")





