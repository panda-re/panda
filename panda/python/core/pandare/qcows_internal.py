#!/usr/bin/env python3
'''
Module for fetching generic PANDA images and managing their metadata.
'''

import logging
import random
import hashlib
from os import path, remove, makedirs
from subprocess import Popen, PIPE, CalledProcessError
from collections import namedtuple
from shlex import split as shlex_split
from sys import exit, stderr
from shutil import move

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

VM_DIR = path.join(path.expanduser("~"), ".panda")

class Image(namedtuple('Image', ['arch', 'os', 'prompt', 'cdrom', 'snapshot', 'url', 'alternate_urls', 'extra_files', 'qcow', 'default_mem', 'extra_args', 'hashes'])):
    '''
    The Image class stores information about a supported PANDA image

    Args:
        arch (str): Arch for the given architecture.
        os (str): an os string we can pass to panda with -os
        prompt (regex): a regex to detect a bash prompt after loading the snapshot and sending commands
        cdrom (str): name to use for cd-drive when inserting an ISO via monitor
        qcow (str): optional name to save qcow as
        url (str): url to download the qcow (e.g. https:// website.com/yourqcow.qcow2)
        default_mem (str): memory to use for the root snapshot (e.g. 1G)
        extra_files (list): other files (assumed to be in same directory on server) that we also need
        extra_args (list): Extra arguments to pass to PANDA (e.g. ['-display', 'none'])
        hashes (dict, optional): Mapping between qcow filenames and SHA1hashes they should match upon download
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

    'aarch64_focal': Image(
            arch='aarch64',
            os="linux-64-ubuntu:5.4.0-58-generic-arm64",
            prompt=rb"root@ubuntu-panda:.*# ",
            #cdrom="scsi0-cd2", # No idea what this should be
            default_mem='1G',
            snapshot="root",
            url="https://panda-re.mit.edu/qcows/linux/ubuntu/2004/aarch64/ubuntu20_04-aarch64.qcow",
            extra_files=['ubuntu20_04-aarch64-flash0.qcow'],
            extra_args='-nographic -machine virt -cpu cortex-a57 -drive file={DOT_DIR}/ubuntu20_04-aarch64-flash0.qcow,if=pflash,readonly=on'.format(DOT_DIR=VM_DIR)),

    'mips64': Image(
            arch='mips64',
            os="linux-64-debian:4.14.0-3-5kc-malta", # XXX: NO OSI
            prompt=rb"root@debian-buster-mips:.*# ",
            cdrom="ide1-cd0", # not sure
            snapshot="root",
            url="https://panda-re.mit.edu/qcows/linux/debian/10/mips64/debian-buster-mips.qcow2",
            default_mem='2g',
            extra_files=['vmlinux-4.14.0-3-5kc-malta.mips.buster', 'initrd.img-4.14.0-3-5kc-malta.mips.buster'],
            extra_args='-M malta -cpu MIPS64R2-generic -append "root=/dev/vda console=ttyS0 mem=2048m net.ifnames=0 nokaslr" -netdev user,id=user.0 -device virtio-net,netdev=user.0 -device usb-kbd -device usb-tablet -kernel {DOT_DIR}/vmlinux-4.14.0-3-5kc-malta.mips.buster -initrd {DOT_DIR}/initrd.img-4.14.0-3-5kc-malta.mips.buster -nographic'.format(DOT_DIR=VM_DIR)),

    'mips_wheezy': Image(
            arch='mips',
            os="linux-32-debian:3.2.0-4-4kc-malta",
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
            extra_args='-M malta -kernel {DOT_DIR}/vmlinux-3.2.0-4-4kc-malta.mipsel -append "root=/dev/sda1" -nographic'.format(DOT_DIR=VM_DIR),
            hashes={'vmlinux-3.2.0-4-4kc-malta': '592e384a4edc16dade52a6cd5c785c637bcbc9ad',
                    'debian_7.3_mipsel.qcow': 'eeb5de0128a95c5f0d76c4f2161afd1bb320d85b'}),

    'mips_buildroot5':  Image(
            arch='mips',
            os = "linux-32-buildroot:5.10.7-4kc-malta",
            prompt=rb"# ",
            cdrom="ide1-cd0",
            snapshot="root",
            default_mem='1g',
            url="https://panda-re.mit.edu/qcows/linux/buildroot/5.10/mips/mips32_buildroot.qcow",
            extra_files=['mips32_vmlinux-5.10.7-4kc-malta',],
            extra_args='-M malta -kernel {DOT_DIR}/mips32_vmlinux-5.10.7-4kc-malta -net nic,model=pcnet -net user -append "root=/dev/hda" -nographic'.format(DOT_DIR=VM_DIR)),


    'mipsel_buildroot5':  Image(
            arch='mipsel',
            os = "linux-32-buildroot:5.10.7-4kc-malta-el",
            prompt=rb"# ",
            cdrom="ide1-cd0",
            snapshot="root",
            default_mem='1g',
            url="https://panda-re.mit.edu/qcows/linux/buildroot/5.10/mipsel/mipsel32_buildroot.qcow",
            extra_files=['mipsel32_vmlinux-5.10.7-4kc-malta-el',],
            extra_args='-M malta -kernel {DOT_DIR}/mipsel32_vmlinux-5.10.7-4kc-malta-el -net nic,model=pcnet -net user -append "root=/dev/hda" -nographic'.format(DOT_DIR=VM_DIR)),


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
            alternate_urls=["https://www.dropbox.com/s/4avqfxqemd29i5j/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow2?dl=1"],
            extra_args="-display none",
            hashes={"bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow2": "556305921c8250537bbbfbb57cb56f9ef07f4d63"}),
}
"""
Dictionary of `Image` objects by name.
Generic values (underlying OS version may change) include:
    x86_64
    i386
    ppc
    arm
    aarch64
    mips
    mipsel
    mips64

You may also specify an exact arch/OS combination from the following exist:
    x86_64_ubuntu_1804
    i386_ubuntu_1604
    ppc_wheezy
    arm_wheezy
    aarch64 _focal
    mips_wheezy
    mips_buildroot5
    mipsel_wheezy
    mipsel_buildroot5
    mips64
""" # TODO: autogenerate values here

# Default values
SUPPORTED_IMAGES['x86_64']  = SUPPORTED_IMAGES['x86_64_ubuntu_1804']
SUPPORTED_IMAGES['i386']    = SUPPORTED_IMAGES['i386_ubuntu_1604']
SUPPORTED_IMAGES['ppc']     = SUPPORTED_IMAGES['ppc_wheezy']
SUPPORTED_IMAGES['arm']     = SUPPORTED_IMAGES['arm_wheezy']
SUPPORTED_IMAGES['aarch64'] = SUPPORTED_IMAGES['aarch64_focal']
SUPPORTED_IMAGES['mips']    = SUPPORTED_IMAGES['mips_wheezy']
SUPPORTED_IMAGES['mipsel']  = SUPPORTED_IMAGES['mipsel_wheezy']
SUPPORTED_IMAGES['mips64']    = SUPPORTED_IMAGES['mips64']

class Qcows():
    '''
    Helper library for managing qcows on your filesystem.
    Given an architecture, it can download a qcow from `panda.mit.edu` to `~/.panda/` and then use that.
    Alternatively, if a path to a qcow is provided, it can just use that.
    A qcow loaded by architecture can then be queried to get the name of the root snapshot or prompt.
    '''

    @staticmethod
    def get_qcow_info(name=None):
        '''
        Get information about supported image as specified by name.

        Args:
            name (str): String idenfifying a qcow supported
                
        Returns:
            Image: Instance of the Image class for a qcow
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

    @staticmethod
    def get_qcow(name=None, download=True, _is_tty=True):
        '''
        Given a generic name of a qcow in `pandare.qcows.SUPPORTED_IMAGES` or a path to a qcow, return the path. Defaults to i386

        Args:
            name (str): generic name or path to qcow
            download (bool, default True): should the qcow be downloaded if necessary
                
        Returns:
            string: Path to qcow

        Raises:
            ValueError: if download is set to False and the qcow is not present
            RuntimeError: if the architecture is unsupported or the necessary files could not be downloaded
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

        # We need to downlaod if the QCOW or any extra files are missing
        # If the files are present on disk, assume they're okay
        needs_download = not path.isfile(qcow_path)

        if not needs_download:
            for extra_file in image_data.extra_files or []:
                extra_file_path = path.join(VM_DIR, extra_file)
                if not path.isfile(extra_file_path):
                    needs_download = True
                    break

        if needs_download and download:
            Qcows.download_qcow(image_data, qcow_path, _is_tty=_is_tty)
        elif needs_download:
            raise ValueError("Qcow is not on disk and download option is disabled")

        return qcow_path

    @staticmethod
    def get_file(urls, output_path, sha1hash=None, do_retry=True, _is_tty=True):
        assert len(urls) > 0
        url = random.choice([x for x in urls if x is not None])

        if _is_tty:
            print(f"Downloading required file: {url}")
            cmd = ["wget", '--show-progress', '--quiet', url, "-O", output_path+".tmp"]
        else:
            print(f"Please wait for download of required file: {url}", file=stderr)
            cmd = ["wget", "--quiet", url, "-O", output_path+".tmp"]

        try:
            with Popen(cmd, stdout=PIPE, bufsize=1, universal_newlines=True) as p:
                for line in p.stdout:
                    print(line, end='')

            if p.returncode != 0:
                raise CalledProcessError(p.returncode, p.args)

            # Check hash if we have one
            if sha1hash is not None:
                if _is_tty:
                    print(f"Validating file hash")
                sha1 = hashlib.sha1()

                with open(output_path+".tmp", 'rb') as f:
                    while True:
                        data = f.read(65536) #64kb chunks
                        if not data:
                            break
                        sha1.update(data)
                computed_hash = sha1.hexdigest()
                if computed_hash != sha1hash:
                    raise ValueError(f"{url} has hash {computed_hash} vs expected hash {sha1hash}")
                # Hash matches, move .tmp file to actual path
                move(output_path+".tmp", output_path)
            else:
                # No hash, move .tmp file to actual path
                move(output_path+".tmp", output_path)
                

        except Exception as e:
            logger.info("Download failed, deleting partial file: %s", output_path)
            remove(output_path+".tmp")

            if do_retry:
                if _is_tty and do_retry:
                    print("Hash mismatch - retrying")
                Qcows.get_file([url], output_path, sha1hash, do_retry=False, _is_tty=_is_tty)
            else:
                # Not retrying again, fatal - leave any partial files though
                raise RuntimeError(f"Unable to download expeted file from {url} even after retrying: {e}") from None
        logger.debug("Downloaded %s to %s", url, output_path)

    @staticmethod
    def download_qcow(image_data, output_path, _is_retry=False, _is_tty=True):
        '''
        Download the qcow described in the Image object in image_data
        Store to the output output_path.
        If the Image includes SHA1 hashes, validate the file was downloaded correctly, otherwise retry once
        '''

        # Check if we have a hash for the base qcow. Then download and vlidate with that hash
        qcow_base = image_data.url.split("/")[-1] if '/' in image_data.url else image_data.url
        base_hash = None

        if image_data.hashes is not None and qcow_base in image_data.hashes:
            base_hash = image_data.hashes[qcow_base]

        Qcows.get_file([image_data.url] + (image_data.alternate_urls if image_data.alternate_urls is not None else []), output_path, base_hash, _is_tty=_is_tty)

        # Download all extra files out of the same directory
        url_base = image_data.url[:image_data.url.rfind("/")] + "/"  # Truncate url to last /
        for extra_file in image_data.extra_files or []:
            extra_file_path = path.join(VM_DIR, extra_file)
            extra_hash = None
            if image_data.hashes is not None and extra_file in image_data.hashes:
                extra_hash = image_data.hashes[extra_file]
            Qcows.get_file([url_base + extra_file], extra_file_path, extra_hash, _is_tty=_is_tty) # TODO: support alternate URL here too? Won't work for some hosting options

    @staticmethod
    def qcow_from_arg(idx=1):
        '''
        Given an index into argv, call get_qcow with that arg if it exists, else with None

        Args:
            idx (int): an index into argv
                
        Returns:
            string: Path to qcow
        '''
        from sys import argv

        if len(argv) > idx:
            return Qcows.get_qcow(argv[idx])
        else:
            return Qcows.get_qcow()

    @staticmethod
    def remove_image(target):
        try:
            qcow = Qcows.get_qcow(target, download=False)
        except ValueError:
            # No QCOW, we're good!
            return

        try:
            image_data = SUPPORTED_IMAGES[target]
        except ValueError:
            # Not a valid image? I guess we're good
            return

        qc = image_data.qcow
        if not qc: # Default, get name from url
            qc = image_data.url.split("/")[-1]
        qcow_path = path.join(VM_DIR, qc)
        remove(qcow_path)

        for extra_file in image_data.extra_files or []:
            extra_file_path = path.join(VM_DIR, extra_file)
            if path.isfile(extra_file_path):
                remove(extra_file_path)
