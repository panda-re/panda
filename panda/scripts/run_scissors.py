import argparse
import subprocess32
from plog_reader import PLogReader
from collections import namedtuple
from run_guest import *
from tempdir import TempDir
from os.path import basename, dirname, join
from google.protobuf.json_format import MessageToJson
import IPython


Arch = namedtuple('Arch', ['dir', 'binary', 'prompt', 'qcow', 'os', 'extra_files', 'extra_args'])
Arch.__new__.__defaults__ = (None,None)

SUPPORTED_ARCHES = {
    'i386': Arch('i386-softmmu', 'qemu-system-i386', "root@debian-i386:~#", "wheezy_panda2.qcow2", 'linux-32-lava32'),
    # 'x86_64': Arch('x86_64-softmmu', 'qemu-system-x86_64', "root@debian-amd64:~#", "wheezy_x64.qcow2"),
    # 'ppc': Arch('ppc-softmmu', 'qemu-system-ppc', "root@debian-powerpc:~#", "ppc_wheezy.qcow"),
    # 'arm': Arch('arm-softmmu', 'qemu-system-arm', "root@debian-armel:~#", "arm_wheezy.qcow", 
    #     extra_files=['vmlinuz-3.2.0-4-versatile', 'initrd.img-3.2.0-4-versatile'],
    #     extra_args='-M versatilepb -append "root=/dev/sda1" -kernel {DOT_DIR}/vmlinuz-3.2.0-4-versatile -initrd {DOT_DIR}/initrd.img-3.2.0-4-versatile')
}

USAGE='''
This will use asidstory and scissors to snip out a piece of a replay given a process name of interest. 
Asidstory searches for the first rr instruction count 
'''

home_dir = os.getenv("HOME")
dot_dir = join(home_dir, '.panda')

this_script = os.path.abspath(__file__)
this_script_dir = dirname(this_script)
default_build_dir = join(dirname(dirname(this_script_dir)), 'build')
panda_build_dir = os.getenv("PANDA_BUILD", default_build_dir)

def qemu_binary(arch_data):
    return join(panda_build_dir, arch_data.dir, arch_data.binary)

# def run_asidstory(qemu):
#     subprocess.call()

# def run_scissors(qemu):
#     subprocess.call()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage=USAGE)

    parser.add_argument("--arch", action='store', default='i386', choices=SUPPORTED_ARCHES.keys())
    parser.add_argument("--replay", required=True)
    parser.add_argument("--snapshot", "-s", action='store', default="root")
    parser.add_argument("--process")
    parser.add_argument("--qcow")

    args = parser.parse_args()

    arch_data = SUPPORTED_ARCHES[args.arch]

    qemu_path = qemu_binary(arch_data)
    if args.qcow:
        qcow = args.qcow
    else:
        qcow = join(dot_dir, arch_data.qcow)

    asidstory_args = "-replay {} -os {} -panda asidstory -pandalog asidstory_plog".format(args.replay, arch_data.os).split(" ")
    if args.process == None:
        args.process = os.path.basename(args.replay)

    qemu_args = [qemu_path, qcow]
    qemu_args.extend(asidstory_args)

    progress("Running qemu with args:")
    print qemu_args
    print subprocess32.list2cmdline(qemu_args)

    qemu = subprocess32.call(qemu_args) # , stdout=DEVNULL, stderr=DEVNULL)

    # with TempDir() as tmpdir, Qemu(qemu_path, qcow, args.snapshot, tmpdir, expect_prompt= arch_data.prompt, extra_args=extra_args) as qemu:

    instr_ranges = []
    with PLogReader("asidstory_plog") as plr:
        for i, m in enumerate(plr):
            if i > 0: print(',')
            if m.asid_info.name == args.process:
                instr_ranges.append((m.asid_info.start_instr, m.asid_info.end_instr))
            # IPython.embed()

    print instr_ranges
    start_instr = instr_ranges[1][0]
    end_instr = instr_ranges[1][1]
    start_instr = start_instr + (end_instr + start_instr)/2

    scissors_args = "-replay {} -panda scissors:name={}_snipped,start={},end={}".format(args.replay, args.replay, start_instr, end_instr).split(" ")
    qemu_args = [qemu_path, qcow]
    qemu_args.extend(scissors_args)

    progress("Running qemu with args:")
    print qemu_args
    print subprocess32.list2cmdline(qemu_args)

    qemu = subprocess32.call(qemu_args) # , stdout=DEVNULL, stderr=DEVNULL)

