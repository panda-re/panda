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
from os.path import abspath, join, realpath
from subprocess32 import STDOUT
from traceback import print_exception

from expect import Expect
from tempdir import TempDir

debug = True

def env_to_list(env):
    return ["{}='{}'".format(k, v) for k, v in env.iteritems()]

def progress(msg):
    print Fore.GREEN + '[run_guest.py] ' + Fore.RESET + Style.BRIGHT + msg + Style.RESET_ALL
    print

class Qemu(object):
    def __init__(self, qemu_path, qcow, snapshot, tempdir, expect_prompt,
                 boot=False, rr=False, perf=False, extra_args=None):
        assert not (perf and rr)
        self.qemu_path = qemu_path
        self.qcow = qcow
        self.snapshot = snapshot
        self.tempdir = tempdir
        self.rr = rr
        self.perf = perf
        self.boot = boot
        self.expect_prompt = expect_prompt
        self.extra_args = extra_args or []

    # types a command into the qemu monitor and waits for it to complete
    def run_monitor(self, cmd):
        if debug:
            print "monitor cmd: [%s]" % cmd
        print Style.BRIGHT + "(qemu)" + Style.RESET_ALL,
        self.monitor.sendline(cmd)
        self.monitor.expect("(qemu)")
        print
        print

    def type_console(self, cmd):
        assert (not self.boot)
        if debug:
            print "console cmd: [%s]" % cmd
        self.console.send(cmd)

    # types a command into the guest os and waits for it to complete
    def run_console(self, cmd=None, timeout=30):
        assert (not self.boot)
        if cmd is not None:
            self.type_console(cmd)
        print Style.BRIGHT + self.expect_prompt + Style.RESET_ALL,
        self.console.sendline()
        self.console.expect(self.expect_prompt, timeout=timeout)
        print
        print

    def __enter__(self):
        monitor_path = join(self.tempdir, 'monitor')
        if not self.boot:
            serial_path = join(self.tempdir, 'serial')

        qemu_args = [self.qemu_path, self.qcow]
#        if not self.boot:
#
        qemu_args.extend(['-monitor', 'unix:{},server,nowait'.format(monitor_path)])
        if self.boot:
            qemu_args.append('-S')
        else:
            qemu_args.extend(['-serial', 'unix:{},server,nowait'.format(serial_path),
                              '-loadvm', self.snapshot])
        qemu_args.extend(['-display', 'none'])
        qemu_args.extend(self.extra_args)
        if self.rr: qemu_args = ['rr', 'record'] + qemu_args
        if self.perf: qemu_args = ['perf', 'record'] + qemu_args

        progress("Running qemu with args:")
        print subprocess32.list2cmdline(qemu_args)

        self.qemu = subprocess32.Popen(qemu_args) # , stdout=DEVNULL, stderr=DEVNULL)
        while not os.path.exists(monitor_path):
            time.sleep(0.1)
        if not self.boot:
            while not os.path.exists(serial_path):
                time.sleep(0.1)
#        while not all([os.path.exists(p) for p in [monitor_path, serial_path]]):
#            time.sleep(0.1)

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

    def __exit__(self, exc_type, exc_value, traceback):
        if traceback:
            print_exception(exc_type, exc_value, traceback)
        else:
            self.monitor.sendline("quit")
            self.monitor_socket.close()
            if not self.boot:
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

def create_boot_recording(qemu_path, qcow, recording_path, boot_time):
    DEVNULL = open(os.devnull, "w")

    recording_path = realpath(recording_path)

    with TempDir() as tempdir, Qemu(qemu_path, qcow, None, tempdir, \
                                    boot=True, rr=None) as qemu:

        # start PANDA recording
        qemu.run_monitor("begin_record \"{}\"".format(recording_path))
        qemu.run_monitor("cont")
        # wait for this long
        time.sleep(boot_time)
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
