#!/usr/bin/env python2.7
import json
import os
import pipes
import socket
import subprocess32
import sys
import time

from colorama import Fore, Style
from errno import EEXIST
from os.path import abspath, basename, dirname, join, realpath
from subprocess32 import STDOUT
from traceback import print_exception

from expect import Expect
from tempdir import TempDir

debug = True

def progress(msg):
    print
    print Fore.GREEN + '[run_guest.py] ' + Fore.RESET + Style.BRIGHT + msg + Style.RESET_ALL

class Qemu(object):
    def __init__(self, qemu_path, qcow, snapshot, tempdir):
        self.qemu_path = qemu_path
        self.qcow = qcow
        self.snapshot = snapshot
        self.tempdir = tempdir

    # types a command into the qemu monitor and waits for it to complete
    def run_monitor(self, cmd):
        if debug:
            print "monitor cmd: [%s]" % cmd
        print Style.BRIGHT + "(qemu)" + Style.RESET_ALL,
        self.monitor.sendline(cmd)
        self.monitor.expect("(qemu)")
        print

    def type_console(self, cmd):
        if debug:
            print "\n\nconsole cmd: [%s]" % cmd
        self.console.send(cmd)

    # types a command into the guest os and waits for it to complete
    def run_console(self, cmd=None, timeout=30, expectation="root@debian-i386:~#"):
        if cmd is not None:
            self.type_console(cmd)
        print Style.BRIGHT + "root@debian-i386:~#" + Style.RESET_ALL,
        self.console.sendline()
        self.console.expect(expectation, timeout=timeout)
        print

    def __enter__(self):
        monitor_path = join(self.tempdir, 'monitor')
        serial_path = join(self.tempdir, 'serial')

        qemu_args = [self.qemu_path, self.qcow, '-loadvm', self.snapshot,
                        '-monitor', 'unix:{},server,nowait'.format(monitor_path),
                        '-serial', 'unix:{},server,nowait'.format(serial_path),
                        '-display', 'none']

        progress("Running qemu with args:")
        print subprocess32.list2cmdline(qemu_args)

        DEVNULL = open(os.devnull, "w")
        self.qemu = subprocess32.Popen(qemu_args, stdout=DEVNULL, stderr=DEVNULL)
        while not all([os.path.exists(p) for p in [monitor_path, serial_path]]):
            time.sleep(0.1)

        self.monitor_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.monitor_socket.connect(monitor_path)
        self.serial_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.serial_socket.connect(serial_path)

        self.monitor = Expect(self.monitor_socket)
        self.console = Expect(self.serial_socket)

        # Make sure monitor/console are in right state.
        self.monitor.expect("(qemu)")
        print
        self.console.sendline()
        self.console.expect("root@debian-i386:~#")
        print

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if traceback:
            print_exception(exc_type, exc_value, traceback)
        else:
            self.monitor.sendline("quit")
            self.monitor_socket.close()
            self.serial_socket.close()

        try:
            self.qemu.wait(timeout=3)
        except subprocess32.TimeoutExpired:
            progress("Qemu stailed. Sending SIGTERM...")
            self.qemu.terminate()

        print

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
def create_recording(qemu_path, qcow, snapshot, command, copy_directory, recording_path):
    DEVNULL = open(os.devnull, "w")

    recording_path = realpath(recording_path)
    directory = dirname(recording_path)
    exename = basename(command[0])
    isoname = join(directory, exename + '.iso')

    progress("Creaing ISO {}...".format(isoname))
    make_iso(copy_directory, isoname)

    with TempDir() as tempdir, Qemu(qemu_path, qcow, snapshot, tempdir) as qemu:
        progress("Inserting CD...")
        qemu.run_monitor("change ide1-cd0 \"{}\"".format(isoname))
        qemu.run_console("mkdir -p {}".format(pipes.quote(copy_directory)))
        # Make sure cdrom didn't automount
        # Make sure guest path mirrors host path
        qemu.run_console("while ! mount /dev/cdrom {}; ".format(pipes.quote(copy_directory)) +
                    "do sleep 0.3; umount /dev/cdrom; done")

        # Important that we type command into console before recording starts and only
        # hit enter once we've started the recording.
        progress("Running command inside guest.")
        qemu.type_console(subprocess32.list2cmdline(command))

        # start PANDA recording
        qemu.run_monitor("begin_record \"{}\"".format(recording_path))
        qemu.run_console(timeout=1200)

        # end PANDA recording
        progress("Ending recording...")
        qemu.run_monitor("end_record")

    DEVNULL.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print >>sys.stderr, "Usage: python project.json"
        sys.exit(1)

    project_file = abspath(sys.argv[1])
    project = json.load(open(project_file, "r"))

    # *** Required json fields
    # path to qemu exec (correct guest)
    assert 'qemu' in project
    # name of snapshot from which to revert which will be booted & logged in as root?
    assert 'snapshot' in project
    # directory in which to create recording.
    assert 'directory' in project
    # command line to run the target program
    assert 'command' in project
    # path to guest qcow
    assert 'qcow' in project
    # name of project
    assert 'name' in project
    # path to project on host
    assert 'install_dir' in project
    # recording name
    assert 'recording_name' in project

    try:
        os.makedirs(project['directory'])
    except OSError as e:
        if e.errno != EEXIST:
            raise

    create_recording(
        project['qemu'],
        project['qcow'],
        project['snapshot'],
        project['command'].format(install_dir=project['install_dir']),
        project['install_dir'],
        join(project['directory'], project['recording_name'])
    )
