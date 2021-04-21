# Helper utilities functions and classes for use in pypanda.
'''
Misc helper functions
'''

from colorama import Fore, Style
from functools import wraps
from os import devnull
from subprocess import check_call, STDOUT
from sys import platform
from threading import current_thread, main_thread

# Set to enable pypanda debugging
debug = False

def progress(msg):
    """
    Print a message with a green "[PYPANDA]" prefix
    """
    print(Fore.GREEN + '[PYPANDA] ' + Fore.RESET + Style.BRIGHT + msg +Style.RESET_ALL)

def warn(msg):
    """
    Print a message with a red "[PYPANDA]" prefix
    """
    print(Fore.RED + '[PYPANDA] ' + Fore.RESET + Style.BRIGHT + msg +Style.RESET_ALL)

def make_iso(directory, iso_path):
    '''
    Generate an iso from a directory
    '''
    with open(devnull, "w") as DEVNULL:
        if platform.startswith('linux'):
            check_call([
                'genisoimage', '-RJ', '-max-iso9660-filenames', '-o', iso_path, directory
            ], stderr=STDOUT if debug else DEVNULL)
        elif platform == 'darwin':
            check_call([
                'hdiutil', 'makehybrid', '-hfs', '-joliet', '-iso', '-o', iso_path, directory
            ], stderr=STDOUT if debug else DEVNULL)
        else:
            raise NotImplementedError("Unsupported operating system!")

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

def blocking(func):
    """
    Decorator to ensure a function isn't run in the main thread
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        assert (current_thread() is not main_thread()), "Blocking function run in main thread"
        return func(*args, **kwargs)
    wrapper.__blocking__ = True
    wrapper.__name__ = func.__name__ + " (with async thread)"
    return wrapper

class GArrayIterator():
    '''
    Iterator which will run a function on each iteration incrementing
    the second argument. Useful for GArrays with an accessor function
    that takes arguments of the GArray and list index. e.g., osi's
    get_one_module.
    '''
    def __init__(self, func, garray, garray_len, cleanup_fn):
        self.garray = garray
        self.garray_len = garray_len
        self.current_idx = 0
        self.func = func
        self.cleanup_func = cleanup_fn

    def __iter__(self):
        self.current_idx = 0
        return self

    def __next__(self):
        if self.current_idx >= self.garray_len:
            raise StopIteration
        # Would need to make this configurable before using MappingIter with other types
        ret = self.func(self.garray, self.current_idx)
        self.current_idx += 1
        return ret

    def __del__(self):
        self.cleanup_func(self.garray)

class plugin_list(dict):
    '''
    Wrapper class around list of active C plugins
    '''
    def __init__(self,panda):
        self._panda = panda
        super().__init__()
    def __getitem__(self,plugin_name):
        if plugin_name not in self:
            self._panda.load_plugin(plugin_name)
        return super().__getitem__(plugin_name)
