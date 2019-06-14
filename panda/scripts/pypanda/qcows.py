# Helper library for managing qcows on your filesystem.
# Given an architecture, it can download a qcow from moyix to ~/.panda/ and then use that
# Given a path to a qcow, it can use that
# A qcow loaded by architecture can then be queried to get the name of the root snapshot or prompt

import os
import subprocess
import logging
from sys import argv
from collections import namedtuple


logging.basicConfig(level=logging.DEBUG)

# TODO: add os_version strings for most archs
Arch = namedtuple('Arch', ['dir',        'binary',             'os',                              'prompt',                  'qcow',                'cdrom',    'snapshot',
                            'extra_files', 'extra_args'])
Arch.__new__.__defaults__ = (None,None)
SUPPORTED_ARCHES = {
        'i386':   Arch('i386-softmmu',   'qemu-system-i386',   "linux-32-debian:3.2.0-4-686-pae", "root@debian-i386:~# ",    "wheezy_panda2.qcow2", "ide1-cd0", "root"),
        'x86_64': Arch('x86_64-softmmu', 'qemu-system-x86_64', "TODO",                            "root@debian-amd64:~# ",   "wheezy_x64.qcow2",    "ide1-cd0", "root"),
        'ppc':    Arch('ppc-softmmu',    'qemu-system-ppc',    "TODO",                            "root@debian-powerpc:~# ", "ppc_wheezy.qcow",     "ide1-cd0", "root"),
        'arm':    Arch('arm-softmmu',    'qemu-system-arm',    "TODO",                            "root@debian-armel:~# ",   "arm_wheezy.qcow",     "scsi0-cd2", "root", 
            extra_files=['vmlinuz-3.2.0-4-versatile', 'initrd.img-3.2.0-4-versatile'],
            extra_args='-M versatilepb -append "root=/dev/sda1" -kernel {DOT_DIR}/vmlinuz-3.2.0-4-versatile -initrd {DOT_DIR}/initrd.img-3.2.0-4-versatile')
        }

VM_DIR = os.path.join(os.path.expanduser("~"), ".panda")

def get_qcow_info(name=None):
    if name is None:
        logging.warning("No qcow name provided. Defaulting to i386")
        name = "i386"

    if os.path.isfile(name):
        raise RuntimeError("TODO: can't automatically determine system info from custom qcows. Use one of: {}".format(", ".join(SUPPORTED_ARCHES.keys())))

    name = name.lower() # Case insensitive. Assumes supported_arches keys are lowercase
    if name not in SUPPORTED_ARCHES.keys():
        raise RuntimeError("Architecture {} is not in list of supported names: {}".format(name, ", ".join(SUPPORTED_ARCHES.keys())))

    r = SUPPORTED_ARCHES[name]
    return r

# Given a generic name of a qcow or a path to a qcow, return the path. Defaults to i386
def get_qcow(name=None):
    if name is None:
        logging.warning("No qcow name provided. Defaulting to i386")
        name = "i386"

    if os.path.isfile(name):
        logging.debug("Provided qcow name appears to be a path, returning it directly: %s", name)
        return name

    name = name.lower() # Case insensitive. Assumes supported_arches keys are lowercase
    if name not in SUPPORTED_ARCHES.keys():
        raise RuntimeError("Architecture {} is not in list of supported names: {}".format(name, ", ".join(SUPPORTED_ARCHES.keys())))

    arch_data = SUPPORTED_ARCHES[name]
    qcow_path = os.path.join(VM_DIR,arch_data.qcow)
    os.makedirs(VM_DIR, exist_ok=True)

    if not os.path.isfile(qcow_path):
        print("\nQcow {} doesn't exist. Downloading from moyix. Thanks moyix!\n".format(arch_data.qcow))
        try:
            subprocess.check_call(["wget", "http://panda.moyix.net/~moyix/" + arch_data.qcow, "-O", qcow_path])
            for extra_file in arch_data.extra_files or []:
                extra_file_path = join(VM_DIR, extra_file)
                subprocess.check_call(["wget", "http://panda.moyix.net/~moyix/" + extra_file, "-O", extra_file_path])
        except Exception as e:
            logging.info("Download failed, deleting partial file(s): %s", qcow_path)
            os.remove(qcow_path)
            for extra_file in arch_data.extra_files or []:
                try:
                    os.remove(join(VM_DIR, extra_file))
                except: # Extra files might not exist
                    pass
            raise e # Reraise
        logging.debug("Downloaded %s to %s", arch_data.qcow, qcow_path)
    else:
        logging.debug("Found existing %s at %s", arch_data.qcow, qcow_path)
    return qcow_path

# Given an index into argv, call get_qcow with that arg if it exists, else with None
def qcow_from_arg(idx=1):
    if (len(argv) > idx):
        return get_qcow(argv[idx])
    else:
        return get_qcow()
