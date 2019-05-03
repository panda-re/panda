import os
import subprocess
import logging
from sys import argv
from collections import namedtuple

logging.basicConfig(level=logging.DEBUG)

# Taken from run_debian.py
Arch = namedtuple('Arch', ['dir', 'binary', 'prompt', 'qcow', 'cdrom', 'extra_files', 'extra_args'])
Arch.__new__.__defaults__ = (None,None)
SUPPORTED_ARCHES = {
        'i386': Arch('i386-softmmu', 'qemu-system-i386', "root@debian-i386:~#", "wheezy_panda2.qcow2", "ide1-cd0"),
        'x86_64': Arch('x86_64-softmmu', 'qemu-system-x86_64', "root@debian-amd64:~#", "wheezy_x64.qcow2", "ide1-cd0"),
        'ppc': Arch('ppc-softmmu', 'qemu-system-ppc', "root@debian-powerpc:~#", "ppc_wheezy.qcow", "ide1-cd0"),
        'arm': Arch('arm-softmmu', 'qemu-system-arm', "root@debian-armel:~#", "arm_wheezy.qcow", "scsi0-cd2", 
            extra_files=['vmlinuz-3.2.0-4-versatile', 'initrd.img-3.2.0-4-versatile'],
            extra_args='-M versatilepb -append "root=/dev/sda1" -kernel {DOT_DIR}/vmlinuz-3.2.0-4-versatile -initrd {DOT_DIR}/initrd.img-3.2.0-4-versatile')
        }
# End code from run_debian

VM_DIR = os.path.join(os.path.expanduser("~"), ".panda")

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

