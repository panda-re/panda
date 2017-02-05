#!/usr/bin/env python2.7
import json
import os
import pipes
import shutil
import socket
import subprocess32
import sys
import tempfile
import time

from colorama import Fore, Style
from os.path import abspath, join
from subprocess32 import STDOUT

from expect import Expect

debug = True

DEVNULL = open(os.devnull, "w")

class TempDir(object):
    def __enter__(self):
        self.path = tempfile.mkdtemp()
        return self.path

    def __exit__(self, exc_type, exc_value, traceback):
        shutil.rmtree(self.path)

def progress(msg):
    print ''
    print Fore.GREEN + '[run_commands.py] ' + Fore.RESET + Style.BRIGHT + msg + Style.RESET_ALL

# types a command into the qemu monitor and waits for it to complete
def run_monitor(cmd):
    if debug:
        print "monitor cmd: [%s]" % cmd
    print Style.BRIGHT + "(qemu)" + Style.RESET_ALL,
    monitor.sendline(cmd)
    monitor.expect("(qemu)")

def type_console(cmd):
    if debug:
        print "\n\nconsole cmd: [%s]" % cmd
    print Style.BRIGHT + "root@debian-i386:~#" + Style.RESET_ALL,
    console.send(cmd)

# types a command into the guest os and waits for it to complete
def run_console(cmd=None, timeout=30, expectation="root@debian-i386:~#"):
    if cmd is not None:
        type_console(cmd)
    console.sendline()
    console.expect(expectation, timeout=timeout)

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
# same directory as in add_queries.sh, under which will be the build
assert 'directory' in project
# command line to run the target program (already instrumented with taint and attack queries)
assert 'command' in project
# path to guest qcow
assert 'qcow' in project
# name of project
assert 'name' in project
# path to project on host
assert 'install_dir' in project
# recording name
assert 'recording_name' in project

installdir = project['install_dir']
panda_log_base_dir = project['directory']
if not os.path.isdir(panda_log_base_dir):
    os.makedirs(panda_log_base_dir)
panda_log_loc = os.path.join(project['directory'],"runcommands")
if os.path.isdir(panda_log_loc):
    shutil.rmtree(panda_log_loc)
os.mkdir(panda_log_loc)
progress("Creating panda log directory {}...".format(panda_log_loc))
panda_log_name = os.path.join(panda_log_loc, project['name'])
isoname = os.path.join(panda_log_loc, project['name']) + ".iso"

progress("Creaing ISO {}...".format(isoname))

if sys.platform.startswith('linux'):
    subprocess32.check_call(['genisoimage', '-RJ', '-max-iso9660-filenames', '-o', isoname, installdir], stderr=DEVNULL)
elif sys.platform == 'darwin':
    subprocess32.check_call(['hdiutil', 'makehybrid', '-hfs', '-joliet', '-iso', '-o', isoname, installdir], stderr=DEVNULL)
else:
    raise NotImplementedError("Unsupported operating system!")

with TempDir() as tempdir:
    monitor_path = join(tempdir, 'monitor')
    serial_path = join(tempdir, 'serial')

    monitor_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    serial_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    qemu_args = [project['qemu'], project['qcow'], '-loadvm', project['snapshot'],
                    '-monitor', 'unix:{},server,nowait'.format(monitor_path),
                    '-serial', 'unix:{},server,nowait'.format(serial_path),
                    '-display', 'none']

    progress("Running qemu with args:")
    print subprocess32.list2cmdline(qemu_args)

    qemu = subprocess32.Popen(qemu_args, stderr=STDOUT)
    while not all([os.path.exists(p) for p in [monitor_path, serial_path]]):
        time.sleep(0.2)

    monitor_socket.connect(monitor_path)
    serial_socket.connect(serial_path)

    monitor = Expect(monitor_socket)
    console = Expect(serial_socket)

    # Make sure monitor/console are in right state.
    monitor.expect("(qemu)")
    console.sendline()
    console.expect("root@debian-i386:~#")
    progress("Inserting CD...")
    run_monitor("change ide1-cd0 {}".format(isoname))
    run_console("mkdir -p {}".format(installdir))
    # Make sure cdrom didn't automount
    # Make sure guest path mirrors host path
    run_console("while ! mount /dev/cdrom {}; ".format(pipes.quote(installdir)) +
                "do sleep 0.3; umount /dev/cdrom; done")

    # run the actual command
    progress("Running command inside guest. Panda log to: {}".format(panda_log_name))

    # Important that we type command into console before recording starts and only
    progress("Running command " + project['command'] + " on guest")
    type_console(project['command'].format(install_dir=installdir))

    # start PANDA recording
    run_monitor("begin_record {}".format(project['recording_name']))
    run_console(timeout=1200)

    # end PANDA recording
    progress("Ending recording...")
    run_monitor("end_record")

    monitor.sendline("quit")

    try:
        qemu.wait(timeout=3)
    except subprocess32.TimeoutExpired:
        qemu.terminate()

    DEVNULL.close()
