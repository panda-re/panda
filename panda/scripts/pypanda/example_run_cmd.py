#!/usr/bin/env python3
import threading
from pypanda import *
from time import sleep
from sys import argv
from enum import Enum
from qcows import get_qcow, get_qcow_info

from colorama import Fore, Style
from os.path import abspath, join, realpath
from os import remove

# No arguments, i386. Otherwise argument should be guest arch
qfile = argv[1] if len(argv) > 1 else None
q = get_qcow_info(qfile)
qf = get_qcow(qfile)

# Initialize panda with a serial device connected
panda = Panda(qcow=qf, os=q.os, serial=True)

@panda.callback.after_machine_init
def machinit(env):
    panda.revert("root") # XXX: why doesn't this work with now=True?
    cmd = "uname -a"
    panda.run_cmd_async(cmd, q.prompt, finished_cb=cmd_finished, finished_cb_args=[cmd])

def cmd_finished(result, cmd):
    print("{} ==> '{}'".format(cmd, result))


@panda.callback.init
def on_init(handle): # After panda is initialized, setup a single callback
    panda.register_callback(handle, panda.callback.after_machine_init, machinit)
    return True

# Set up the panda plugin
panda.load_python_plugin(on_init, "run_cmd")

# Initialize machine
panda.init()

panda.run()

"""
##### FROM RUN_GUEST
def make_iso(directory, iso_path):
    with open(os.devnull, "w") as DEVNULL:
        if sys.platform.startswith('linux'):
            subprocess32.check_call([
                'genisoimage', '-RJ', '-max-iso9660-filenames', '-o', iso_path, directory
            ], stderr=STDOUT if debug else DEVNULL)
        elif sys.platform == 'darwin':
            subprocess32.check_call([
                'hdiutil', 'makehybrid', '-hfs', '-joliet', '-iso', '-o', iso_path, directory
            ], stderr=STDOUT if debug else DEVNULL)
        else:
            raise NotImplementedError("Unsupported operating system!")
# command as array of args.
# copy_directory gets mounted in the same place on the guest as an iso/CD-ROM.
def create_recording(qemu_path, qcow, snapshot, command, copy_directory,
                     recording_path, expect_prompt, isoname=None, rr=False,
                     perf=False, env={}, extra_args=None):
    assert not (rr and perf)

    recording_path = realpath(recording_path)
    if not isoname: isoname = copy_directory + '.iso'

    with TempDir() as tempdir, \
            Qemu(qemu_path, qcow, snapshot, tempdir, rr=rr, perf=perf,
                 expect_prompt=expect_prompt, extra_args=extra_args) as qemu:
        if os.listdir(copy_directory):
            progress("Creating ISO {}...".format(isoname))
            make_iso(copy_directory, isoname)

            progress("Inserting CD...")
            qemu.run_monitor("change ide1-cd0 \"{}\"".format(isoname))
            qemu.run_console("mkdir -p {}".format(pipes.quote(copy_directory)))
            # Make sure cdrom didn't automount
            # Make sure guest path mirrors host path
            qemu.run_console("while ! mount /dev/cdrom {}; ".format(pipes.quote(copy_directory)) +
                        "do sleep 0.3; umount /dev/cdrom; done")

        # if there is a setup.sh script in the replay/proc_name/cdrom/ folder
        # then run that setup.sh script first (good for scriptst that need to
        # prep guest environment before script runs
        qemu.run_console("{}/setup.sh &> /dev/null || true".format(pipes.quote(copy_directory)))
        # Important that we type command into console before recording starts and only
        # hit enter once we've started the recording.
        progress("Running command inside guest.")
        qemu.type_console(subprocess32.list2cmdline(env_to_list(env) + command))

        # start PANDA recording
        qemu.run_monitor("begin_record \"{}\"".format(recording_path))
        qemu.run_console(timeout=1200)

        # end PANDA recording
        progress("Ending recording...")
        qemu.run_monitor("end_record")
"""
