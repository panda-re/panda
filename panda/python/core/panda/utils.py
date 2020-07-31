"""
Useful utilities for use in pypanda.
"""


import sys
import subprocess
import shlex
from os import devnull
from colorama import Fore, Style

# This debug variable
debug = False

def progress(msg):
    """Helpful printing utility"""
    print(Fore.GREEN + '[pypanda.py] ' + Fore.RESET + Style.BRIGHT + msg +Style.RESET_ALL)

def make_iso(directory, iso_path):
    """Generates iso from path"""
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

def telescope(panda, cpu, val):
    '''
    Given a value, check if it's a pointer by seeing if we can map it to physical memory.
    If so, recursively print where it points
    to until
    1) It points to a string (then print the string)
    2) It's code (then disassembly the insn)
    3) It's an invalid pointer
    4) It's the 5th time we've done this, break

    TODO Should use memory protections to determine string/code/data
    '''
    for _ in range(5): # Max chain of 5
        print("-> 0x{:0>8x}".format(val), end="\t")

        if val == 0:
            print()
            return
        # Consider that val points to a string. Test and print
        try:
            str_data = panda.virtual_memory_read(cpu, val, 16)
        except ValueError:
            print()
            return

        str_val = ""
        for d in str_data:
            if d >= 0x20 and d < 0x7F:
                str_val += chr(d)
            else:
                break
        if len(str_val) > 2:
            print("== \"{}\"".format(str_val))
            return


        data = str_data[:4] # Truncate to 4 bytes
        val = int.from_bytes(data, byteorder='little')

    print("-> ...")

