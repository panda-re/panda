
import os
import subprocess as sp
import sys
import re
import shutil 
from colorama import Fore, Style

debug = True

def progress(msg):
    print Fore.GREEN + '[ptest.py] ' + Fore.RESET + Style.BRIGHT + msg + Style.RESET_ALL
    print

def dir_exists(dirname):
    return os.path.exists(dirname) and os.path.isdir(dirname)

def dir_required(dirname):
    if dir_exists(dirname):
        progress("Dir found: " + dirname)
    else:
        progress("Dir missing: " + dirname)
        sys.exit(1)

def file_exists(filename):
    return os.path.exists(filename) and os.path.isfile(filename)

def file_required(filename):
    if file_exists(filename):
        progress("File found: " + filename)
    else:
        progress("File missing: " + filename)
        sys.exit(1)

def moveit(base1, base2, suff):
    print "moving %s%s to %s%s" % (base1, suff, base2, suff)
    shutil.move(base1 + suff, base2 + suff)

def run(cmd):
    if debug:
        progress ("Cmd = " + cmd)
        sp.check_call([cmd]) 
    else:
        DEVNULL = open(os.devnull, "w")
        sp.check_call([cmd], stdout=DEVNULL, stderr=DEVNULL)


pandaregressiondir = "PANDA_REGRESSION_DIR"
assert (pandaregressiondir in os.environ)
pandaregressiondir = os.environ[pandaregressiondir]

thisdir = os.path.dirname(os.path.realpath(__file__))
pandadir = os.path.realpath(thisdir + "/../..")
pandascriptsdir = os.path.realpath(pandadir + "/panda/scripts")
testingscriptsdir = thisdir
qemu = pandadir + "/build/i386-softmmu/qemu-system-i386"

ptest_config = testingscriptsdir + "/config.testing"
if not (file_exists(ptest_config)):
    progress ("ptest_config file missing: " + ptest_config)
    sys.exit(1)
              
maybe_tests = [test.strip() for test in open(ptest_config).readlines()]
enabled_tests = [test for test in maybe_tests if (not test.startswith("#"))]

def the_dir(thing, test):
    return "%s/%s/%s" % (pandaregressiondir, thing, test)

def the_file(thing, test):
    return "%s/%s" % (the_dir(thing,test), test)

def the_replayfile(test):
    return the_file("replays", test)

def the_blessedfile(test):
    return the_file("blessed", test) + ".out"

def the_tmpoutfile(test):
    return the_file("tmpout", test) + ".out"

# this will only succeed if called from setup or test script
foo = re.search("([^/]+)-([setup|test]).*.py", sys.argv[0])
if foo:
    testname = foo.groups()[0]
    replaydir = the_dir("replay", testname)
    blesseddir = the_dir("blessed", testname)
    tmpoutdir = the_dir("tmpout", testname)
    replayfile = the_replayfile(testname)
    blessedfile = the_blessedfile(testname)
    tmpoutfile = the_tmpoutfile(testname)
