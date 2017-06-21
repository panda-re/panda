#!/usr/bin/env python2.7

USAGE="""run_on_32bitlinux.py [args] binary

So you want to try panda but dont have any replays.  Poor you.
This script allows you to run commands on a 32-bit linux guest.

1st arg is binary which should be a 32-bit ELF.
Remaining arguments are the args that binary needs. Files on the host will
automatically be copied to the guest, unless the argument is prefixed with
"guest:". This works for the binary too.

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

Advanced USAGE:

    --rr turns on Mozilla rr record for your command

    --arch specifies another architecture (Default is i386)

    --env "PYTHON_DICT" where PYTHON_DICT represents the user environment
                         you would like to enforce on the guest
        eg.  --env "{'CC':'/bin/gcc', 'LD_LIBRARY_PATH':'/usr/bin/gcc'}"

"""

SUPPORTED_ARCHES = {
    'i386': ('i386-softmmu', 'qemu-system-i386', "root@debian-i386:~#", "wheezy_panda2.qcow2"),
    'ppc': ('ppc-softmmu', 'qemu-system-ppc', "root@debian-powerpc:~#", "ppc_wheezy.qcow")
}


import os
import shutil
import subprocess as sp
import sys
import argparse

from os.path import basename, dirname, join
from run_guest import create_recording

home_dir = os.getenv("HOME")
dot_dir = join(home_dir, '.panda')

if not (os.path.exists(dot_dir)):
    os.mkdir(dot_dir)

this_script = os.path.abspath(__file__)
this_script_dir = dirname(this_script)
default_build_dir = join(dirname(dirname(this_script_dir)), 'build')
panda_build_dir = os.getenv("PANDA_BUILD", default_build_dir)

filemap = {}


def transform_arg_copy(orig_filename):
    if orig_filename.startswith('guest:'):
        return orig_filename[6:]
    elif os.path.exists(orig_filename):
        name = basename(orig_filename)
        copy_filename = join(install_dir, name)
        if copy_filename != orig_filename:
            shutil.copy(orig_filename, copy_filename)
        filemap[orig_filename] = copy_filename
        return copy_filename
    else:
        return orig_filename

def EXIT_USAGE():
    print(USAGE)
    sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage=USAGE)

    parser.add_argument("--rr", action='store_true', dest='rr',)
    parser.add_argument("guest_args", metavar='guest_arg', nargs='+')
    parser.add_argument("--env", action='store', dest='env')
    parser.add_argument("--arch", action='store', dest='arch', default='i386')

    args = parser.parse_args()

    if len(sys.argv) < 2:
        EXIT_USAGE()

    rr = False
    if args.rr:
        rr = True
    
    (qemu_softmmu, qemu_binary, expect_prompt, qcow_fname) = SUPPORTED_ARCHES[args.arch]

    env = {}
    if args.env:
        try:
            env = eval(args.env)
        except:
            print("Something went wrong parsing the environment string: [{}]".format(env))
            EXIT_USAGE()

    guest_cmd = args.guest_args
    binary = args.guest_args[0]

    if binary.startswith('guest:'): binary = binary[6:]
    binary_basename = basename(binary)

    # Directory structure:
    # + replays
    # +---+ binary1
    #     +---- cdrom
    #     +---- cdrom.iso
    binary_dir = join(os.getcwd(), 'replays', binary_basename)
    if not os.path.exists(binary_dir):
        os.makedirs(binary_dir)

    install_dir = join(binary_dir, 'cdrom')
    # if os.path.exists(install_dir):
        # shutil.rmtree(install_dir)
    if not os.path.exists(install_dir):
        os.mkdir(install_dir)

    qcow = join(dot_dir, qcow_fname)
    if not os.path.isfile(qcow):
        print "\nYou need a qcow. Downloading from moyix. Thanks moyix!\n"
        sp.check_call(["wget", "http://panda.moyix.net/~moyix/" + qcow_fname, "-O", qcow])

    new_guest_cmd = map(transform_arg_copy, guest_cmd)
    exename = basename(new_guest_cmd[0])

    print "args =", guest_cmd
    print "new_guest_cmd =", new_guest_cmd
    print "env = ", env

    create_recording(
        join(panda_build_dir, qemu_softmmu, qemu_binary),
        qcow, "root", new_guest_cmd,
        install_dir,
        join(binary_dir, binary_basename),
        expect_prompt,
        rr=rr,
        env=env,
    )
