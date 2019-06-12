#!/usr/bin/env python3

import socket
import pdb
from pypanda import *
from time import sleep
from sys import argv
from enum import Enum
from qcows import get_qcow, get_qcow_info
from panda_expect import Expect
from tempfile import NamedTemporaryFile

from colorama import Fore, Style
from os.path import abspath, join, realpath
from os import remove

# No arguments, i386. Otherwise argument should be guest arch
qfile = argv[1] if len(argv) > 1 else None
q = get_qcow_info(qfile)
qf = get_qcow(qfile)
extra_args = []

serial_file = NamedTemporaryFile(prefix="pypanda_").name
extra_args.extend(['-serial', 'unix:{},server,nowait'.format(serial_file)])
extra_args.extend(['-loadvm', 'root']) # TODO want to remove this
extra_str = " ".join(extra_args)
# Initialize panda with a serial device connected
panda = Panda(qcow=qf, extra_args=extra_str)

class State(Enum):
    PRE_INIT = 0
    INIT = 1
    CMD_SENT = 2
    GOT_RESPONSE = 3
    DONE = 4

state = State.PRE_INIT
console = None
serial_socket = None
nr = 0

@panda.callback.after_machine_init
def machinit(env):
    global state
    global serial_socket
    global serial_file

    progress("Machine initialized -- disabling chaining & reverting to booted snapshot\n")
    panda.disable_tb_chaining()
    #panda.revert("root", now=True) # TODO: Want this uncommented
    pc = panda.current_pc(env)

    # Connect to python from serial device
    serial_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    serial_socket.connect(serial_file)
    print("Connected to {}".format(serial_file))
    state = State.INIT


@panda.callback.before_block_exec
def before_block_exec(env,tb):
    global nr
    global serial_socket
    global serial_file
    global console
    global state
    nr +=1

    if state == State.INIT:
        console = Expect(serial_socket, quiet=True)
        progress("Executing `uname -a` in guest")
        console.sendline(b"uname -a")
        state = State.CMD_SENT

    elif state == State.CMD_SENT and (nr % 100000) == 0: # Check if we have results after ever 100k BBs
        if console.has_buffer(q.prompt):
            print("Got result: ", repr(console.consume_buffer()))

            serial_socket.close()
            remove(serial_file)
            state = State.DONE

    return 0

# Plugin initialization
@panda.callback.init
def init(handle):
    panda.register_callback(handle, panda.callback.after_machine_init, machinit)
    panda.register_callback(handle, panda.callback.before_block_exec, before_block_exec)
    return True

panda.load_python_plugin(init, "run_cmd")
progress ("--- pypanda done with run_cmd plugin init")

panda.init()
progress ("--- pypanda done with init")

panda.run()

"""

    def __enter__(self):
        monitor_path = join(self.tempdir, 'monitor')
        if not self.boot:
            serial_path = join(self.tempdir, 'serial')

        qemu_args = [self.qemu_path, self.qcow]

        if self.rr: qemu_args = ['rr', 'record'] + qemu_args
        if self.perf: qemu_args = ['perf', 'record'] + qemu_args

        progress("Running qemu with args:")
        print subprocess32.list2cmdline(qemu_args)

        self.qemu = subprocess32.Popen(qemu_args)
        while not os.path.exists(monitor_path):
            time.sleep(0.1)
        if not self.boot:
            while not os.path.exists(serial_path):
                time.sleep(0.1)

        self.monitor_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.monitor_socket.connect(monitor_path)
        self.monitor = Expect(self.monitor_socket)
        if not self.boot:
            self.serial_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.serial_socket.connect(serial_path)
            self.console = Expect(self.serial_socket)

        # Make sure monitor/console are in right state.
        self.monitor.expect("(qemu)")
        print
        if not self.boot:
            self.console.sendline()
            self.console.expect(self.expect_prompt)
        print
        print
        return self



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
