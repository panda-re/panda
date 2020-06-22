# Helper library for managing qcows on your filesystem.
# Given an architecture, it can download a qcow from moyix to ~/.panda/ and then use that
# Given a path to a qcow, it can use that
# A qcow loaded by architecture can then be queried to get the name of the root snapshot or prompt

import os
import subprocess
import logging
from sys import argv
from collections import namedtuple


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

VM_DIR = os.path.join(os.path.expanduser("~"), ".panda")

# TODO: add os_version strings are mostly just made up to specify 32 bit?
Arch = namedtuple('Arch', ['dir',        'arch',    'binary',             'os',                              'prompt',                  'qcow',                'cdrom',    'snapshot',
                            'extra_files', 'extra_args'])
Arch.__new__.__defaults__ = (None,None)
SUPPORTED_ARCHES = {
        'i386':   Arch('i386-softmmu',   'i386',   'qemu-system-i386',   "linux-32-debian:3.2.0-4-686-pae", rb"root@debian-i386:.*# ",    "wheezy_panda2.qcow2", "ide1-cd0", "root",
            extra_args='-display none'),
        'x86_64': Arch('x86_64-softmmu', 'x86_64', 'qemu-system-x86_64', "linux-64-debian:3.2.0-4-amd64", rb"root@debian-amd64:.*# ",   "wheezy_x64.qcow2",    "ide1-cd0", "root",
            extra_args='-display none'),
        'ppc':    Arch('ppc-softmmu',    'ppc',    'qemu-system-ppc',    "linux-32-debian:3.2.0-4-ppc-pae",   rb"root@debian-powerpc:.*# ", "ppc_wheezy.qcow",     "ide1-cd0", "root",
            extra_args='-display none'),
        # XXX: generic ARM guest is currently broken
        'arm':    Arch('arm-softmmu',    'arm',    'qemu-system-arm',    "linux-32-debian:3.2.0-4-arm-pae",   rb"root@debian-armel:.*# ",   "arm_wheezy.qcow",     "scsi0-cd2", "root",
            extra_files=['vmlinuz-3.2.0-4-versatile', 'initrd.img-3.2.0-4-versatile'],
            extra_args='-display none -M versatilepb -append "root=/dev/sda1" -kernel {DOT_DIR}/vmlinuz-3.2.0-4-versatile -initrd {DOT_DIR}/initrd.img-3.2.0-4-versatile'.format(DOT_DIR=VM_DIR)),
        'mips':    Arch('mips-softmmu',    'mips',    'qemu-system-mips',    "linux-32-debian:3.2.0-4-4kc-malta",   None,   "debian_wheezy_mips_standard.qcow",     "ide1-cd0", "root",
            extra_files=['vmlinux-3.2.0-4-4kc-malta',],
            extra_args='-M malta -kernel {DOT_DIR}/vmlinux-3.2.0-4-4kc-malta -append "root=/dev/sda1" -nographic'.format(DOT_DIR=VM_DIR)),
        'mipsel':  Arch('mipsel-softmmu',    'mipsel',     'qemu-system-mipsel',    "linux-32-debian:3.2.0-4-4kc-malta",   None,   "debian_wheezy_mipsel_standard.qcow2",     "ide1-cd0", "root",
            extra_files=['vmlinux-3.2.0-4-4kc-malta.mipsel',],
            extra_args='-M malta -kernel {DOT_DIR}/vmlinux-3.2.0-4-4kc-malta.mipsel -append "root=/dev/sda1" -nographic'.format(DOT_DIR=VM_DIR))
        }

def get_qcow_info(name=None):
    if name is None:
        logger.warning("No qcow name provided. Defaulting to i386")
        name = "i386"

    if os.path.isfile(name):
        raise RuntimeError("TODO: can't automatically determine system info from custom qcows. Use one of: {}".format(", ".os.path.join(SUPPORTED_ARCHES.keys())))

    name = name.lower() # Case insensitive. Assumes supported_arches keys are lowercase
    if name not in SUPPORTED_ARCHES.keys():
        raise RuntimeError("Architecture {} is not in list of supported names: {}".format(name, ", ".join(SUPPORTED_ARCHES.keys())))

    r = SUPPORTED_ARCHES[name]
    return r

# Given a generic name of a qcow or a path to a qcow, return the path. Defaults to i386
def get_qcow(name=None):
    if name is None:
        logger.warning("No qcow name provided. Defaulting to i386")
        name = "i386"

    if os.path.isfile(name):
        logger.debug("Provided qcow name appears to be a path, returning it directly: %s", name)
        return name

    name = name.lower() # Case insensitive. Assumes supported_arches keys are lowercase
    if name not in SUPPORTED_ARCHES.keys():
        raise RuntimeError("Architecture {} is not in list of supported names: {}".format(name, ", ".os.path.join(SUPPORTED_ARCHES.keys())))

    arch_data = SUPPORTED_ARCHES[name]
    qcow_path = os.path.join(VM_DIR,arch_data.qcow)
    os.makedirs(VM_DIR, exist_ok=True)

    if not os.path.isfile(qcow_path):
        print("\nQcow {} doesn't exist. Downloading from moyix. Thanks moyix!\n".format(arch_data.qcow))
        try:
            subprocess.check_call(["wget", "--quiet", "http://panda.moyix.net/~moyix/" + arch_data.qcow, "-O", qcow_path])
            for extra_file in arch_data.extra_files or []:
                extra_file_path = os.path.join(VM_DIR, extra_file)
                subprocess.check_call(["wget", "--quiet", "http://panda.moyix.net/~moyix/" + extra_file, "-O", extra_file_path])
        except Exception as e:
            logger.info("Download failed, deleting partial file(s): %s", qcow_path)
            os.remove(qcow_path)
            for extra_file in arch_data.extra_files or []:
                try:
                    os.remove(os.path.join(VM_DIR, extra_file))
                except: # Extra files might not exist
                    pass
            raise e # Reraise
        logger.debug("Downloaded %s to %s", arch_data.qcow, qcow_path)
    return qcow_path

# Given an index into argv, call get_qcow with that arg if it exists, else with None
def qcow_from_arg(idx=1):
    if (len(argv) > idx):
        return get_qcow(argv[idx])
    else:
        return get_qcow()
