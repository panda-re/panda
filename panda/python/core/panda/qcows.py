from os import path, remove, makedirs
import logging
from sys import argv
from subprocess import check_call
from collections import namedtuple


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

VM_DIR = path.join(path.expanduser("~"), ".panda")

class Image(namedtuple('Image', ['arch', 'os', 'prompt', 'cdrom', 'snapshot', 'url', 'extra_files', 'qcow', 'default_mem', 'extra_args'])):
    '''
    The Image class stores information about a supported PANDA image:

        Fields:
            arch : Arch for the given architecture.
            os : an os string we can pass to panda with -os
            prompt : a regex to detect a bash prompt after loading the snapshot and sending commands
            cdrom : name to use for cd-drive when inserting an ISO via monitor
            qcow : optional name to save qcow as
            url : url to download the qcow (e.g. https:// website.com/yourqcow.qcow2)
            default_mem : memory to use for the root snapshot (e.g. 1G)
            extra_files : other files (assumed to be in same directory on server) that we also need
            extra_args : Extra arguments to pass to PANDA (e.g. '-nographic')
    '''

Image.__new__.__defaults__ = (None,) * len(Image._fields)

SUPPORTED_IMAGES = {
    # Debian: support for 4 arches on Wheezy
    'i386_wheezy': Image(
            arch = 'i386',
            os="linux-32-debian:3.2.0-4-686-pae",
            prompt=rb"root@debian-i386:.*# ",
            qcow="wheezy_panda2.qcow2", # Backwards compatability
            cdrom="ide1-cd0",
            snapshot="root",
            default_mem='128M',
            url="https://panda-re.mit.edu/qcows/linux/debian/7.3/x86/debian_7.3_x86.qcow",
            extra_args="-display none"),

    'x86_64_wheezy': Image(
            arch='x86_64',
            os="linux-64-debian:3.2.0-4-amd64",
            prompt=rb"root@debian-amd64:.*# ",
            qcow="wheezy_x64.qcow2",# Backwards compatability 
            cdrom="ide1-cd0",
            snapshot="root",
            default_mem='128M',
            url="https://panda-re.mit.edu/qcows/linux/debian/7.3/x86_64/debian_7.3_x86_64.qcow",
            extra_args="-display none"),

    'ppc_wheezy': Image(
            arch='ppc',
            os="linux-64-debian:3.2.0-4-ppc-pae",
            prompt=rb"root@debian-powerpc:.*# ",
            qcow="ppc_wheezy.qcow2",# Backwards compatability 
            cdrom="ide1-cd0",
            default_mem='128M',
            snapshot="root",
            url="https://panda-re.mit.edu/qcows/linux/debian/7.3/ppc/debian_7.3_ppc.qcow",
            extra_args="-display none"),

    'arm_wheezy': Image(
            arch='arm',
            os="linux-32-debian:3.2.0-4-versatile-arm",
            prompt=rb"root@debian-armel:.*# ",
            qcow="arm_wheezy.qcow",# Backwards compatability 
            cdrom="scsi0-cd2",
            default_mem='128M',
            snapshot="root",
            url="https://panda-re.mit.edu/qcows/linux/debian/7.3/arm/debian_7.3_arm.qcow",
            extra_files=['vmlinuz-3.2.0-4-versatile', 'initrd.img-3.2.0-4-versatile'],
            extra_args='-display none -M versatilepb -append "root=/dev/sda1" -kernel {DOT_DIR}/vmlinuz-3.2.0-4-versatile -initrd {DOT_DIR}/initrd.img-3.2.0-4-versatile'.format(DOT_DIR=VM_DIR)),

    'mips_wheezy': Image(
            arch='mips',
            os="linux-64-debian:3.2.0-4-arm-pae", # XXX wrong
            prompt=rb"root@debian-mips:.*# ",
            cdrom="ide1-cd0",
            snapshot="root",
            url="https://panda-re.mit.edu/qcows/linux/debian/7.3/mips/debian_7.3_mips.qcow",
            default_mem='1g',
            extra_files=['vmlinux-3.2.0-4-4kc-malta'],
            extra_args='-M malta -kernel {DOT_DIR}/vmlinux-3.2.0-4-4kc-malta -append "root=/dev/sda1" -nographic'.format(DOT_DIR=VM_DIR)),

    'mipsel_wheezy':  Image(
            arch='mipsel',
            os = "linux-32-debian:3.2.0-4-4kc-malta",
            prompt=rb"root@debian-mipsel:.*# ",
            cdrom="ide1-cd0",
            snapshot="root",
            default_mem='1g',
            url="https://panda-re.mit.edu/qcows/linux/debian/7.3/mipsel/debian_7.3_mipsel.qcow",
            extra_files=['vmlinux-3.2.0-4-4kc-malta.mipsel',],
            extra_args='-M malta -kernel {DOT_DIR}/vmlinux-3.2.0-4-4kc-malta.mipsel -append "root=/dev/sda1" -nographic'.format(DOT_DIR=VM_DIR)),

    # Ubuntu: x86/x86_64 support for 16.04, x86_64 support for 18.04
    'i386_ubuntu_1604': Image(
            arch = 'i386',
            os="linux-32-ubuntu:4.4.200-170-generic", # Version.c is 200 but name is 4.4.0. Not sure why
            prompt=rb"root@instance-1:.*#",
            cdrom="ide1-cd0",
            snapshot="root",
            default_mem='1024',
            url="https://panda-re.mit.edu/qcows/linux/ubuntu/1604/x86/ubuntu_1604_x86.qcow",
            extra_args="-display none"),

    #'x86_64_ubuntu_1604': Image( # XXX: This one is broken
    #        arch='x86_64',
    #        os="linux-64-ubuntu:4.4.0-180-pae",
    #        prompt=rb"root@instance-1:.*#",
    #        cdrom="ide1-cd0",
    #        snapshot="root",
    #        default_mem='1024',
    #        url="https://panda-re.mit.edu/qcows/linux/ubuntu/1604/x86_64/ubuntu_1604_x86_64.qcow",
    #        extra_files=['xenial-server-cloudimg-amd64-disk1.img',],
    #        extra_args="-display none"),

    'x86_64_ubuntu_1804': Image(
            arch='x86_64',
            os="linux-64-ubuntu:4.15.0-72-generic-noaslr-nokaslr",
            prompt=rb"root@ubuntu:.*#",
            cdrom="ide1-cd0",
            snapshot="root",
            default_mem='1024',
            url="https://panda-re.mit.edu/qcows/linux/ubuntu/1804/x86_64/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow2",
            extra_args="-display none"),
}

# Default values
SUPPORTED_IMAGES['x86_64'] = SUPPORTED_IMAGES['x86_64_ubuntu_1804']
SUPPORTED_IMAGES['i386']   = SUPPORTED_IMAGES['i386_ubuntu_1604']
SUPPORTED_IMAGES['ppc']    = SUPPORTED_IMAGES['ppc_wheezy']
SUPPORTED_IMAGES['arm']    = SUPPORTED_IMAGES['arm_wheezy']
SUPPORTED_IMAGES['mips']   = SUPPORTED_IMAGES['mips_wheezy']
SUPPORTED_IMAGES['mipsel'] = SUPPORTED_IMAGES['mipsel_wheezy']

class Qcows():
    '''
    Helper library for managing qcows on your filesystem.
    Given an architecture, it can download a qcow from panda-re.mit.edu to ~/.panda/ and then use that.
    Alternatively, if a path to a qcow is provided, it can just use that.
    A qcow loaded by architecture can then be queried to get the name of the root snapshot or prompt
    '''

    def get_qcow_info(name=None):
        '''
        Return information about supported image as specified by name.

            Parameters:
                name: python string idenfifying a qcow supported
            
            Returns:
                Image class for qcow
        '''
        if name is None:
            logger.warning("No qcow name provided. Defaulting to i386")
            name = "i386"

        if path.isfile(name):
            raise RuntimeError("TODO: can't automatically determine system info from custom qcows. Use one of: {}".format(", ".join(SUPPORTED_IMAGES.keys())))

        name = name.lower() # Case insensitive. Assumes supported_arches keys are lowercase
        if name not in SUPPORTED_IMAGES.keys():
            raise RuntimeError("Architecture {} is not in list of supported names: {}".format(name, ", ".join(SUPPORTED_IMAGES.keys())))

        r = SUPPORTED_IMAGES[name]
        # Move properties in .arch to being in the main object
        return r

    def get_qcow(name=None):
        '''
        Given a generic name of a qcow or a path to a qcow, return the path. Defaults to i386

            Parameters:
                name: generic name or path to qcow
            
            Returns:
                path to qcow
        '''
        if name is None:
            logger.warning("No qcow name provided. Defaulting to i386")
            name = "i386"

        if path.isfile(name):
            logger.debug("Provided qcow name appears to be a path, returning it directly: %s", name)
            return name

        name = name.lower() # Case insensitive. Assumes supported_images keys are lowercase
        if name not in SUPPORTED_IMAGES.keys():
            raise RuntimeError("Architecture {} is not in list of supported names: {}".format(name, ", ".join(SUPPORTED_IMAGES.keys())))

        image_data = SUPPORTED_IMAGES[name]
        qc = image_data.qcow
        if not qc: # Default, get name from url
            qc = image_data.url.split("/")[-1]
        qcow_path = path.join(VM_DIR,qc)
        makedirs(VM_DIR, exist_ok=True)

        if not path.isfile(qcow_path):
            print("\nQcow {} doesn't exist. Downloading from https://panda-re.mit.edu. Thanks MIT!\n".format(qc))
            try:
                check_call(["wget", "--quiet", image_data.url, "-O", qcow_path])
                for extra_file in image_data.extra_files or []:
                    extra_file_path = path.join(VM_DIR, extra_file)
                    url = image_data.url[:image_data.url.rfind("/")] + "/" + extra_file # Truncate url to last /, then add extra_file
                    check_call(["wget", "--quiet", url, "-O", extra_file_path])
            except Exception as e:
                logger.info("Download failed, deleting partial file(s): %s", qcow_path)
                remove(qcow_path)
                for extra_file in image_data.extra_files or []:
                    try:
                        remove(path.join(VM_DIR, extra_file))
                    except: # Extra files might not exist
                        pass
                raise e # Reraise
            logger.debug("Downloaded %s to %s", qc, qcow_path)
        return qcow_path

    def qcow_from_arg(idx=1):
        '''
        Given an index into argv, call get_qcow with that arg if it exists, else with None
        '''
        if (len(argv) > idx):
            return get_qcow(argv[idx])
        else:
            return get_qcow()
