#!/usr/bin/env python3
'''
Module to simplify PANDA command line usage. Use python3 -m pandare.qcows to 
fetch files necessary to run various generic VMs and generate command lines to start them.
Also supports deleting previously-fetched files
'''

import logging
from os import path, remove, makedirs
from subprocess import check_call
from collections import namedtuple
from shlex import split as shlex_split
from sys import exit

from .panda import Panda
from os import environ
from .qcows_internal import Qcows, SUPPORTED_IMAGES

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

VM_DIR = path.join(path.expanduser("~"), ".panda")
class Qcows_cli():
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
            if os.path.isfile(extra_file_path):
                remove(extra_file_path)
    @staticmethod
    def cli(target):
        q = Qcows.get_qcow_info(target)
        qcow = Qcows.get_qcow(target)
        arch = q.arch
        build_dir = Panda._find_build_dir(arch, find_executable=True)
        panda_args = [build_dir + f"/{arch}-softmmu/panda-system-{arch}"]
        biospath = path.realpath(path.join(build_dir, "pc-bios"))
        panda_args.extend(["-L", biospath])
        panda_args.extend(["-os", q.os])

        if arch == 'mips64':
            panda_args.extend(["-drive", f"file={qcow},if=virtio"])
        else:
            panda_args.append(qcow)

        panda_args.extend(['-m', q.default_mem])

        if q.extra_args:
            extra_args = shlex_split(q.extra_args)
            for x in extra_args:
                if " " in x:
                    panda_args.append(repr(x))
                else:
                    panda_args.append(x)

        panda_args.extend(['-loadvm', q.snapshot])

        ret = " ".join(panda_args)

        if "-display none" in ret:
            ret = ret.replace("-display none", "-nographic")

        # Repalce /home/username with ~ when we can
        if 'HOME' in environ:
            ret = ret.replace(environ['HOME'], '~')
        return ret

if __name__ == "__main__":
    from sys import argv, stdout
    valid_names = "\n * ".join(SUPPORTED_IMAGES.keys())

    delete_mode = False
    if len(argv) == 3 and argv[1] == 'delete':
        delete_mode = True
        argv.pop(1)

    if len(argv) != 2 or argv[1] not in SUPPORTED_IMAGES:
        print("\n" + f"USAGE: {argv[0]} [target_images]\n" +
                     f"   or: {argv[0]} delete [target_image]\n\n" +
                      "The required files for the specified images will be downloaded and the PANDA command line to emulate that guest will be printed.\n" +
                      "If the \"delete\" argument is passed, any files related to the image will be deleted and no command line will be printed"
                     f"Where target_images is one of:\n * {valid_names}\n")
        exit(1)

    if delete_mode:
        Qcows_cli.remove_image(argv[1])

    else:
        cmd = Qcows_cli.cli(argv[1])
        if stdout.isatty():
            print(f"Run the generic {argv[1]} PANDA guest interactively with the following command:\n{cmd}")
        else:
            print(cmd)
