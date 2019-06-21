#!/usr/bin/env python3

from pypanda import *
from sys import argv
import subprocess
import os
import shlex

from qcows import get_qcow, get_qcow_info

# No arguments, i386. Otherwise argument should be guest arch
qfile = argv[1] if len(argv) > 1 else None
q = get_qcow_info(qfile)
qf = get_qcow(qfile)
panda = Panda(qcow=qf, os=q.os, expect_prompt=q.prompt)

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

@alwaysasync
def run_cmd():
    # XXX Expose configuration
    guest_command = "/mnt/bin/jq . /mnt/inputs/fixed.json"
    copy_directory = "/tmp/jqB" # Host directory with file
    iso_name="test.iso"
    recording_name="recording"

    panda.revert_imprecise("root")

    if copy_directory:
        # Make iso
        if not iso_name: iso_name = copy_directory + '.iso'

        # If there's a directory, build an ISO and put it in the cddrive
        assert(os.listdir(copy_directory)), "TODO: support non-ISO guest commands" # TODO
        progress("Creating ISO {}...".format(iso_name))
        make_iso(copy_directory, iso_name)

        # 1) we insert the CD drive
        panda.run_monitor_cmd("change ide1-cd0 \"{}\"".format(iso_name))

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
        panda.run_serial_cmd(setup_sh)

    # TODO: type command before running

    # 3) start recording
    panda.run_monitor_cmd("begin_record {}".format(recording_name))

    # 4) run commmand
    panda.run_serial_cmd(guest_command)

    # 5) End recording
    panda.run_monitor_cmd("end_record")

    print("Finished recording")


@alwaysasync
def quit():
    print("Finished with run_cmd, let's quit")
    panda.run_monitor_cmd("quit")


@panda.callback.init
def on_init(handle): # After panda is initialized, setup a single callback
    #panda.register_callback(handle, panda.callback.before_block_exec, before_block_execute)
    return True

# Set up the panda plugin
panda.load_python_plugin(on_init, "run_cmd")

panda.queue_async(run_cmd)
panda.queue_async(quit)

panda.run()
