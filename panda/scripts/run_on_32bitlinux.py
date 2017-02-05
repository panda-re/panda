#!/usr/bin/env python2.7

"""run_on_32bitlinux.py binary [args]

So you want to try panda but dont have any recordings.  Poor you.
This script allows you to run commands on a 32-bit linux guest.

1st arg is binary which should be a 32-bit ELF.
Remaining arguments are the args that binary needs. Files on the host will
automatically be copied to the guest, unless the argument is prefixed with
"guest:". This works for the binary too.

For example,

run_on_32bitlinux.py foo2

will copy into the guest the binary foo2 (which needs to be in the cwd) and
create a recording of running it under a panda 32-bit wheezy machine.

run_on_32bitlinux.py guest:/bin/cat guest:/etc/passwd

will create a recording of running the guest's cat on the guest's /etc/passwd.

The recording files will be in

./rcp-panda/foo2-recording*

You can replay with

$PANDA_DIR/build/i386-softmmu/qemu-system-i386 -replay ./rcp-panda/ps-recording

Assuming PANDA_DIR is path to your panda directory and you built under
the build dir. If you built somewhere else, set PANDA_BUILD env to your build
dir.

"""

import os
import json
import pipes
import shutil
import subprocess as sp
import sys

from os.path import basename, dirname, join

home_dir = os.getenv("HOME")
dot_dir = join(home_dir, '.panda')

if not (os.path.exists(dot_dir)):
    os.mkdir(dot_dir)

this_script = os.path.abspath(__file__)
this_script_dir = dirname(this_script)
default_build_dir = join(dirname(dirname(this_script_dir)), 'build')
panda_build_dir = os.getenv("PANDA_BUILD", default_build_dir)

filemap = {}

def filecopy(orig_filename):
    if orig_filename.startswith('guest:'):
        return orig_filename[6:]
    else:
        name = basename(orig_filename)
        copy_filename = join(install_dir, name)
        shutil.copy(orig_filename, copy_filename)
        filemap[orig_filename] = copy_filename
        return copy_filename

binary = sys.argv[1]
args = []
if (len(sys.argv) >= 2):
    args = sys.argv[2:]

# create installdir if necessary

rcp_dir = join(os.getcwd(), 'rcp-panda')
if os.path.exists(rcp_dir):
    shutil.rmtree(rcp_dir)
os.mkdir(rcp_dir)

install_dir = join(rcp_dir, 'install')
if os.path.exists(install_dir):
    shutil.rmtree(install_dir)
os.mkdir(install_dir)

# get qcow if necessary

qcow = join(dot_dir, "wheezy_panda2.qcow2")

if not (os.path.isfile(qcow)):
    print "\nYou need a qcow. Downloading from moyix. Thanks moyix!\n"
    sp.check_call(["wget", "http://panda.moyix.net/~moyix/wheezy_panda2.qcow2", "-O", qcow])

exename = basename(binary)
binary_copy = filecopy(binary)

new_args = []
for arg in args:
    if os.path.exists(arg) or arg.startswith('guest:'):
        new_args.append(filecopy(arg))
    else:
        new_args.append(arg)

print "args =", args
print "new_args =", new_args

proj = {
    "qemu": join(panda_build_dir, 'i386-softmmu', 'qemu-system-i386'),
    "qcow": qcow,
    "snapshot": "root",
    "install_dir": install_dir,
    "directory": rcp_dir,
    "name": exename,
    "recording_name": join(rcp_dir, exename + "-recording"),
    "command": pipes.quote(binary_copy) + " " + sp.list2cmdline(new_args),
}

jsonfile = join(rcp_dir, 'rc.json')
f = open(jsonfile, "w")
json.dump(proj, f)
f.close()

print "jsonfile: [{}]".format(jsonfile)

rcog = join(this_script_dir, "run_guest.py")

cmd = ['python', rcog, jsonfile]

print "cmd = [{}]".format(sp.list2cmdline(cmd))
print "filemap:", filemap

sp.check_call(cmd)
