#!/usr/bin/env python

import argparse
import os
import shutil
import socket
import subprocess
import sys
import telnetlib
import time

USE_TMPDIR=False

def img_check(qcow_path):
    """Run qemu-img check on the qcow and return its return code
    0 = good, 1 = error, 2 = error, 3 = wasted space"""
    checker = subprocess.Popen(["qemu-img", "check", qcow_path], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE)
    out, err = checker.communicate()
    ret_code = checker.returncode
    if 1 == ret_code or 2== ret_code:
        print "Error in modified QCOW, not copying it back"
    return ret_code

def copy_qcow_back(modified_path, old_path):
    ret_code = img_check(modified_path)
    if ret_code == 0:
        if USE_TMPDIR:
            shutil.copyfile(modified_path, old_path)
    else:
        print "warning: QCOW corrupted: ", modified_path
        if not USE_TMPDIR:
            print "QCOW NOW INVALID!!!! Get a new copy before trying to use it again"
        shutil.copyfile(modified_path, old_path+".broken")

parser = argparse.ArgumentParser("Run PANDROID",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--tmpdir", action='store',
                    default=None,
                    help="Copy QCOWs to a temp directory before running QEMU with them. "+
                    "They are only copied back if qemu-img verifies they aren't corrupt.")
fgroup = parser.add_argument_group("image files")
fgroup.add_argument("--cache", default="cache-pandroid.qcow2",
                    help="cache partition QCOW path in imgdir")
parser.add_argument("imgdir", help="directory the qcows are in")
fgroup.add_argument("--system", default="system-pandroid.qcow2",
                    help="system partition QCOW path in imgdir")
fgroup.add_argument("--data", default="data-pandroid.qcow2",
                    help="data partition QCOW path in imgdir")
fgroup.add_argument("--sdcard", default="sdcard.qcow2",
                    help="SD card QCOW path in imgdir")
parser.add_argument("--nameserver", action='append',
                    help="add a nameserver to the guest", default=argparse.SUPPRESS)
rrgroup = parser.add_mutually_exclusive_group()
rrgroup.add_argument("--replay", help="run the specified replay")
rrgroup.add_argument("--record", help="record execution from start")
fgroup.add_argument("--kernel", help="kernel path in imgdir", default="kernel")
fgroup.add_argument("--ramdisk", help="ramdisk path in imgdir", default="initramfs")
parser.add_argument("--tcpdump", help="file to dump network traffic into", default=argparse.SUPPRESS)
parser.add_argument("--cpu", default="cortex-a9",
                    help="CPU model. Default based on API level.")
parser.add_argument("api_level", type=int)
parser.add_argument("--ext4", help="Partitions are block devices intead of raw flash with YAFFS. Default is based on API level",
                    action='store_true', default=argparse.SUPPRESS)
parser.add_argument("panda_args", nargs=argparse.REMAINDER,
                    help="any additional argument are passed to PANDA")
parser.add_argument("--dont-save", action='store_true',
                    help="don't copy the modified QCOWs back from the tmp dir to the img dir, even if they aren't corrupt")
args = parser.parse_args()

cache = os.path.join(args.imgdir, args.cache)
data = os.path.join(args.imgdir, args.data)
system = os.path.join(args.imgdir, args.system)
sdcard = os.path.join(args.imgdir, args.sdcard)
kernel = os.path.join(args.imgdir, args.kernel)
initrd = os.path.join(args.imgdir, args.ramdisk)

fake_block_device = False
cpu = None
replay = None
record = None
KERNEL_CL="console=ttyS0 ndns=2 qemu=1 no_console_suspend=1 qemu.gles=0 android.qemud=ttyS1"
NETWORK_ARGS="-net nic,vlan=1 -net user,vlan=1"

# if we're using a tmpdir
if args.tmpdir is not None:
    USE_TMPDIR = True
    # does the tmpdir exist?
    tmpdir = os.path.join(args.imgdir, args.tmpdir)
    if not os.path.exists(tmpdir):
        os.mkdir(tmpdir)
    # copy the QCOWs to the tmpdir
    for qcow_name in ['cache', 'data', 'system', 'sdcard']:
        oldpath = globals()[qcow_name] # we already set this
        newpath = os.path.join(tmpdir, qcow_name+'.qcow2')
        print "copying {0} to {1}".format(oldpath, newpath)
        shutil.copyfile(oldpath, newpath)
        # update the path to the qcow
        globals()[qcow_name] = newpath

# Set default args based on API revision
if args.api_level > 18: # higher than 4.3
    # have the NAND pretend to be a block device for ext4
    fake_block_device = True
if args.api_level > 12: # higher than 3.1
    # use ARMv7 CPU
    cpu = "cortex-a9"

# parse other options
if hasattr(args, 'ext4'):
    fake_block_device = True
if args.cpu:
    cpu = args.cpu
if hasattr(args, 'nameserver'):
    for i, ns in enumerate(args.nameserver):
        nsip = socket.gethostbyname(ns)
        if i > 0:
            print "warning: QEMU only understands 1 DNS server!"
        else:
            NETWORK_ARGS+= ",dns={0}".format(nsip)
        KERNEL_CL += " net.dns{0}={1} net.eth0.dns{0}={1}".format(i+1, nsip)
if args.replay:
    replay = args.replay
elif args.record:
    record = args.record
if hasattr(args, 'tcpdump'):
    NETWORK_ARGS+= " -net dump,file={0},vlan=1".format(args.tcpdump)

# format the command line
#TODO handle being called from a dir that isn't panda/qemu/
panda_cli = ["arm-softmmu/qemu-system-arm", "-M", "android_arm"]
if cpu:
    panda_cli.extend(["-cpu", cpu])
panda_cli.extend(["-kernel", kernel, "-initrd", initrd,
  '-global', 'goldfish_nand.system_path={0}'.format(system), 
  '-global', 'goldfish_nand.user_data_path={0}'.format(data),
  '-global', 'goldfish_nand.cache_path={0}'.format(cache),
  '-append', KERNEL_CL,
  '-m', '2G', '-no-reboot', '-monitor', 'telnet:localhost:4321,server,nowait',
  '-show-cursor', '-serial', 'stdio', '-serial', 'telnet:localhost:4421,server,nowait',
  '-display', 'sdl', '-global', 'goldfish_mmc.sd_path={0}'.format(sdcard), '-android', '-S'])
panda_cli.extend(NETWORK_ARGS.split())
if replay:
    panda_cli.extend(['-replay', replay])
if fake_block_device:
    panda_cli.extend("-global goldfish_nand.ext4=on".split())
if hasattr(args, 'panda_args'):
    panda_cli.extend(args.panda_args)

print " ".join(panda_cli)
# run PANDA!
panda_task = subprocess.Popen(panda_cli)

time.sleep(10)
monitor = telnetlib.Telnet("localhost", 4321)
monitor.read_until("(qemu) ")
if record:
    monitor.write("begin_record {0}\n".format(record))
    monitor.read_until("(qemu) ")
monitor.write("c\n")
monitor.close()

panda_task.wait()

# clean up
if USE_TMPDIR and not args.dont_save:
    copy_qcow_back(system, os.path.join(args.imgdir, args.system))
    copy_qcow_back(sdcard, os.path.join(args.imgdir, args.sdcard))
    copy_qcow_back(cache, os.path.join(args.imgdir, args.cache))
    copy_qcow_back(data, os.path.join(args.imgdir, args.ramdisk))


