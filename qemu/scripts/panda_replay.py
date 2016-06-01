#!/usr/bin/env python
#
# panda_replay replay_file_pfx [remaining_panda_args]
#
# replay_file_pfx is full path to replay snapshot.  There are three files that should exist:
#
# replay_file_pfx + "-rr.cmd"
# replay_file_pfx + "-rr-nondet.log"
# replay_file_pfx + "-rr-snp"
#
# This script uses the "-rr.cmd" file which contains the commandline used to create the replay
# to figure out how to run the replay.  In particular, it determines the architecture and 
# memory size.  The script then formulates a cmdline with path to correct qemu executable
# and pasts [remaining_panda_args] on the end and ends by running qemu.
#
# You no longer have to guess what the arch & memory are for a recording!

#


import sys
import re
import os
import subprocess

print " " 

script_dir = os.path.dirname(os.path.realpath(__file__))

# first arg should be full path prefix of replay
# subsequent args are 

# determine arch
cmdline = open("%s-rr.cmd" % sys.argv[1]).read()
#print "cmdline = [%s]" % cmdline

arch = None
for arg in cmdline.split():
    foo = re.search("\/([^/]*)-softmmu", arg)
    if foo:
        arch = foo.groups()[0]

assert (not arch is None)

print "panda_replay: deduced arch=[%s]" % arch


mem = "128"
foo = re.search("-m ([0-9]+[MG])", cmdline)
if foo:
    mem = foo.groups()[0]

print "panda_replay: deduced mem=[%s]" % mem


qemu_dir = os.path.realpath(script_dir + "/..") 

print "qemu_dir = [%s]" % qemu_dir

qemu_cmds = "%s/%s-softmmu/qemu-system-%s -m %s -replay " % (qemu_dir, arch, arch, mem)
qemu_cmds += " ".join(sys.argv[1:])


print "panda_replay: qemu cmdline is [%s]" %  qemu_cmds
print "-----------------------------------------------"

subprocess.call(qemu_cmds.split())
