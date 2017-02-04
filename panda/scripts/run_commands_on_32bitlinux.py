#!/usr/bin/env python

"""run_commands_on_32bitlinux.py binary [args]

So you want to try panda but dont have any recordings.  Poor you. 
This script allows you to run commands on a 32-bit linux guest.  

1st arg is binary which should be a 32-bit ELF.
Remaining arguments are the args that binary needs.

For example, 

run_commands_on_32bitlinux.py foo2 

will run the binary foo2 (which needs to be in the cwd) under a panda
32-bit wheezy machine and create a recording.  The recording files will be in

./rcp-panda/foo2-recording*

You can replay with

$PANDA_DIR/build/i386-softmmu/qemu-system-i386 -replay ./rcp-panda/ps-recording

Assuming PANDA_DIR is path to your panda directory and you built under
the build dir.

"""




import os
import sys
import json
import subprocess as sp
import shutil

home_dir = os.getenv("HOME")
dot_dir = home_dir + "/.panda"

if not (os.path.exists(dot_dir)):
    os.mkdir(dot_dir)

this_script = os.path.abspath(__file__)
(this_script_dir, foo) = os.path.split(this_script)

filemap = {}

def filecopy(orig_filename):
    (path,name) = os.path.split(orig_filename)
    copy_filename = install_dir + "/" + name
    shutil.copy(orig_filename, copy_filename)
    filemap[orig_filename] = copy_filename
    return copy_filename

def is_filename(possible_filename):
    if '/' in possible_filename:
        return True

proj = {}
proj["qemu"] = os.path.realpath(this_script_dir + "/../../build/i386-softmmu/qemu-system-i386")

binary = sys.argv[1]
args = []
if (len(sys.argv) >= 2):
    args = sys.argv[2:]

# create installdir if necessary

rcp_dir = os.getcwd() + "/rcp-panda"
if os.path.exists(rcp_dir):
    shutil.rmtree(rcp_dir)
os.mkdir(rcp_dir)

install_dir = rcp_dir + "/install"
if os.path.exists(install_dir):
    shutil.rmtree(install_dir)
os.mkdir(install_dir)


# get qcow if necessary

qcow = dot_dir + "/wheezy_panda2.qcow2"
proj["qcow"] = qcow

if not (os.path.isfile(qcow)):
    print "\nYou need a qcow. Downloading from moyix. Thanks moyix!\n"
    sp.check_call(["wget", "http://panda.moyix.net/~moyix/wheezy_panda2.qcow2", "-O", qcow])


proj["snapshot"] = "root"

(binpath, exename) = os.path.split(binary)

binary_copy = install_dir + "/" + exename

filecopy(binary)

new_args = []
for arg in args:
    if is_filename(arg):
        copyname = filecopy(arg)
        new_args.append(copyname)
    else:
        new_args.append(arg)

print "args = " + (str(args))
print "new_args = " + (str(new_args))    

proj["install_dir"] = install_dir
proj["library_path"] = ""
proj["directory"] = rcp_dir
proj["name"] = exename
proj["recording_name"] = rcp_dir + "/" + exename + "-recording"
proj["command"] = "{install_dir}/" + exename + " " + (" ".join(new_args))
proj["input"] = "/bin/ls"


jsonfile = rcp_dir + "/rc.json"
f = open(jsonfile, "w")
f.write(json.dumps(proj))
f.close()

print "jsonfile: [%s]" % jsonfile


rcog = this_script_dir + '/' + "run_commands_on_guest.py"

cmd = "python " + rcog + " " + jsonfile

print "cmd = [%s]" % cmd

sp.check_call(cmd.split())

