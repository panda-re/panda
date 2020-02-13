import sys
import subprocess
import shlex
from os import devnull
from colorama import Fore, Style

# This debug variable
debug = False

def progress(msg):
    print(Fore.GREEN + '[pypanda.py] ' + Fore.RESET + Style.BRIGHT + msg +Style.RESET_ALL)

def make_iso(directory, iso_path):
    with open(devnull, "w") as DEVNULL:
        if sys.platform.startswith('linux'):
            subprocess.check_call([
                'genisoimage', '-RJ', '-max-iso9660-filenames', '-o', iso_path, directory
            ], stderr=subprocess.STDOUT if debug else DEVNULL)
        elif sys.platform == 'darwin':
            subprocess.check_call([
                'hdiutil', 'makehybrid', '-hfs', '-joliet', '-iso', '-o', iso_path, directory
            ], stderr=subprocess.STDOUT if debug else DEVNULL)
        else:
            raise NotImplementedError("Unsupported operating system!")

def disasemble(panda, addr, size):
    raise NotImplementedError()

