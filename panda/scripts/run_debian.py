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

./replays/{binaryname}

You can replay with

$PANDA_DIR/build/i386-softmmu/qemu-system-i386 -replay ./rcp-panda/ps-recording

Assuming PANDA_DIR is path to your panda directory and you built under
the build dir. If you built somewhere else, set PANDA_BUILD env to your build
dir.

Advanced USAGE:

    --rr turns on Mozilla rr record for your command

    --arch specifies another architecture (Default is i386)
	
    --snapshot specifies loading a different snapshot for your vm (default is "root")
        
    --qcow specifies a path to an alternate qcow (otherwise uses/installs a qcow in $(HOME)/.panda)

    --env "PYTHON_DICT" where PYTHON_DICT represents the user environment
                         you would like to enforce on the guest
        eg.  --env "{'CC':'/bin/gcc', 'LD_LIBRARY_PATH':'/usr/bin/gcc'}"

"""

from collections import namedtuple

Arch = namedtuple('Arch', ['dir', 'binary', 'prompt', 'qcow', 'extra_files', 'extra_args'])
Arch.__new__.__defaults__ = (None,None)

SUPPORTED_ARCHES = {
    'i386': Arch('i386-softmmu', 'qemu-system-i386', "root@debian-i386:~#", "wheezy_panda2.qcow2"),
    'x86_64': Arch('x86_64-softmmu', 'qemu-system-x86_64', "root@debian-amd64:~#", "wheezy_x64.qcow2"),
    'ppc': Arch('ppc-softmmu', 'qemu-system-ppc', "root@debian-powerpc:~#", "ppc_wheezy.qcow"),
    'arm': Arch('arm-softmmu', 'qemu-system-arm', "root@debian-armel:~#", "arm_wheezy.qcow", 
        extra_files=['vmlinuz-3.2.0-4-versatile', 'initrd.img-3.2.0-4-versatile'],
        extra_args='-M versatilepb -append "root=/dev/sda1" -kernel {DOT_DIR}/vmlinuz-3.2.0-4-versatile -initrd {DOT_DIR}/initrd.img-3.2.0-4-versatile')
}


import os
import shlex
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

def qemu_binary(arch_data):
    return join(panda_build_dir, arch_data.dir, arch_data.binary)

def transform_arg_copy(orig_filename):
    if orig_filename.startswith('guest:'):
        return orig_filename[6:]
    elif os.path.isfile(orig_filename):
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

def run_and_create_recording():
    global install_dir
    
    parser = argparse.ArgumentParser(usage=USAGE)

    parser.add_argument("--perf", action='store_true')
    parser.add_argument("--rr", action='store_true')
    parser.add_argument("--cmd", action='store')
    parser.add_argument("--env", action='store')
    parser.add_argument("--qemu_args", action='store', default="")
    parser.add_argument("--qcow", action='store', default="")
    parser.add_argument("--snapshot", "-s", action='store', default="root")
    parser.add_argument("--arch", action='store', default='i386', choices=SUPPORTED_ARCHES.keys())
    parser.add_argument("--fileinput", action='store')
    parser.add_argument("--stdin", action='store_true')
    parser.add_argument("--replaybase", action='store')

    args, guest_cmd = parser.parse_known_args()
    if args.cmd:
        guest_cmd = shlex.split(args.cmd)

    if len(sys.argv) < 2:
        EXIT_USAGE()

    arch_data = SUPPORTED_ARCHES[args.arch]

    env = {}
    if args.env:
        try:
            env = eval(args.env)
        except:
            print("Something went wrong parsing the environment string: [{}]".format(env))
            EXIT_USAGE()

    binary = guest_cmd[0]

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

    if args.qcow:
        qcow = args.qcow
    else:
        qcow = join(dot_dir, arch_data.qcow)

    if not os.path.isfile(qcow):
        print "\nQcow %s doesn't exist. Downloading from moyix. Thanks moyix!\n" % qcow
        sp.check_call(["wget", "http://panda.moyix.net/~moyix/" + arch_data.qcow, "-O", qcow])
        for extra_file in arch_data.extra_files or []:
            extra_file_path = join(dot_dir, extra_file)
            sp.check_call(["wget", "http://panda.moyix.net/~moyix/" + extra_file, "-O", extra_file_path])

    # Expand out the dot dir in extra_args if necessary
    if arch_data.extra_args:
        extra_args = arch_data.extra_args.format(**{'DOT_DIR': dot_dir})
        # And split it
        extra_args = shlex.split(extra_args)
    else:
        extra_args = []

    new_guest_cmd = map(transform_arg_copy, guest_cmd)
    exename = basename(new_guest_cmd[0])

    print "args =", guest_cmd
    print "new_guest_cmd =", new_guest_cmd
    print "env = ", env

    if args.replaybase is None:
        replay_base = join(binary_dir, binary_basename)
    else:
        replay_base = args.replaybase

    create_recording(
        qemu_binary(arch_data),
        qcow, args.snapshot, new_guest_cmd,
        install_dir,
        replay_base,
        arch_data.prompt,
        rr=args.rr,
        perf=args.perf,
        env=env,
        extra_args=extra_args + shlex.split(args.qemu_args)
    )
    return (replay_base, arch_data, args.stdin, args.fileinput, guest_cmd)


if __name__ == "__main__":
    run_and_create_recording()
    
