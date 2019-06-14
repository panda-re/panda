#!/usr/bin/env python3
import threading
from pypanda import *
from time import sleep
from sys import argv
from enum import Enum
import subprocess
import os
import shlex

from qcows import get_qcow, get_qcow_info

from colorama import Fore, Style
from os.path import abspath, join, realpath


## Example library to copy files into a guest and record a program executing
# Basic functionality works but I think I'll merge this into pypanda itself (instead of an example) soon

# No arguments, i386. Otherwise argument should be guest arch
qfile = argv[1] if len(argv) > 1 else None
q = get_qcow_info(qfile)
qf = get_qcow(qfile)

# Initialize panda with a serial device connected
panda = Panda(qcow=qf, os=q.os, serial=True)

def make_iso(directory, iso_path):
    with open(os.devnull, "w") as DEVNULL:
        if sys.platform.startswith('linux'):
            subprocess.check_call([
                'genisoimage', '-RJ', '-max-iso9660-filenames', '-o', iso_path, directory
            ], stderr=subprocess.STDOUT if debug else DEVNULL)
        elif sys.platform == 'darwin':
            subprocess.check_call([
                'hdiutil', 'makehybrid', '-hfs', '-joliet', '-iso', '-o', iso_path, directory
            ], stderr=subprocess.STDOUT if debug else DEVNULL)
        else:
            raise NotImplementedError("Unsupported operating system!")

queue = []
class cmdType(Enum):
    MONITOR = 0
    SERIAL = 1
cmd = namedtuple('Command', 'name type command')

def run_cmds(resp, state):
    # Run the next command from queue with a callback of ourself with state+=1
    if resp:
        print("Result: {}".format(resp))

    if state < len(queue):
        c = queue[state]
        progress("Run {} command via {}".format(c.name, "monitor" if c.type ==cmdType.MONITOR else "guest"))
        if c.type == cmdType.MONITOR:
            panda.send_monitor_async(c.command, finished_cb=run_cmds, finished_cb_args=[state+1])
        elif c.type == cmdType.SERIAL:
            panda.send_serial_async(c.command, q.prompt, finished_cb=run_cmds, finished_cb_args=[state+1])


def run_guest_cmd(guest_command, copy_directory, recording_path_,
                    expect_prompt, recording_name="recording", isoname=None):

    recording_path = realpath(recording_path_)
    if not isoname: isoname = copy_directory + '.iso'

    # Now build up a queue of actions
    global queue

    # If there's a directory, build an ISO and put it in the cddrive
    assert(os.listdir(copy_directory)), "TODO: support non-ISO guest commands" # TODO
    progress("Creating ISO {}...".format(isoname))
    make_iso(copy_directory, isoname)

    # 1) we insert the CD drive
    queue.append(cmd("cd-drive", cmdType.MONITOR, "change ide1-cd0 \"{}\"".format(isoname)))

    # 2) run setup script
    # setup_sh: 
    #   Make sure cdrom didn't automount
    #   Make sure guest path mirrors host path
    #   if there is a setup.sh script in the directory,
    #   then run that setup.sh script first (good for scripts that need to
    #   prep guest environment before script runs)
    
    # TODO XXX: guest filesystem is read only so this could hang forever if it can't mount
    copy_directory="/mnt/" # for now just mount to an existing directory
    # XXX: fix this copy directory hack

    setup_sh = "mkdir -p {mount_dir}; while ! mount /dev/cdrom {mount_dir}; do sleep 0.3; " \
                " umount /dev/cdrom; done; {mount_dir}/setup.sh &> /dev/null || true " \
                    .format(mount_dir = (shlex.quote(copy_directory)))
    queue.append(cmd("setup", cmdType.SERIAL, setup_sh))

    # TODO: we really want to type command, start recording, then press enter on command

    # 3) start recording
    queue.append(cmd("start recording",  cmdType.MONITOR,    "begin_record {}".format(recording_name)))

    # 4) run commmand
    queue.append(cmd("guest_command", cmdType.SERIAL, guest_command))

    # 5) End recording
    queue.append(cmd("end recording",  cmdType.MONITOR,    "end_record"))

    # 5) End recording
    queue.append(cmd("end recording",  cmdType.MONITOR,    "end_record"))

    # Kick off our queue of commands
    run_cmds(None, 0)


@panda.callback.after_machine_init
def machinit(env):
    panda.revert("root")
    run_guest_cmd("/mnt/bin/jq . /mnt/inputs/fixed.json", "/tmp/jqB", "/tmp", q.prompt, "test.iso")

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
