#!/usr/bin/env python3

# Fake files from the hypervisor
# Open problems:
#   Child processes inherit FDs
#   Not all FD-parsing syscalls are hooked
#   Currently just x86_64 and probably i386
#   No support for faking/logging writes to faked FDs

from sys import argv, stdout
from os import path
import enum
import re
import random
from math import ceil
from panda import Panda, blocking, ffi
from panda.x86.helper import * # XXX omg these are 32-bit names

import logging

logger = logging.getLogger('panda.file_hooking')
logger.setLevel(logging.INFO)

# TODO: move PPP decorator into core panda
def ppp(plugin_name, attr):
    def inner(func):
        panda.plugins[plugin_name].__getattr__(attr)(func)
        return func
    return inner

# Classes for tracking faked files by name and FD
class FakedFile:
    def __init__(self, fake_contents=None, faking_fn = None):
        assert(fake_contents or faking_fn), "Must provide fake contents of faking fn"
        self.fake_contents = fake_contents
        self.faking_fn = faking_fn
    def get_size(self, bytesize):
        if self.fake_contents:
            return ceil(len(self.fake_contents)/bytesize)
        raise NotImplementedError("Can't get size of a function-hooked fake file")

class HyperFile:
    def __init__(self,  filename, is_fake=False, offset=0):
        self.filename = filename
        self.is_fake = is_fake
        self.offset = offset
        self.first_read = True

# To hook files we maintain two mappings
#   path regex -> fake contents OR faking fn
#       If multiple wildcards trigger, we just use the first
#   FDs -> [is_fake, file_offset]
#       file_offset is meaningless unless is_fake is True


files_faked = {} # name: (fake_contents, faking_fn)

file_descriptors = {} # (FD, CR3): HyperFile with filename set to a value from files_faked if fake


def add_file(name, contents=None, fn=None):
    '''
    Register hooks for a file with a name that supports * for wildcards.
        Note that the guest may access files just by name without path.
        E.g., cd /dev; cat foo would just be triggered for name='foo', not
        '/dev/foo'

    If contents are set they will be returned to the guest.  Otherwise, if
    fn is set, it will be called with arguments of offset, size and should
    return data
    '''
    assert(contents or fn), "Must set contents or fn"
    r_name = re.compile(name.replace("*", ".*"))
    files_faked[r_name] = FakedFile(contents, fn)

def is_hooked(fd, cr3):
    return (fd, cr3) in file_descriptors and file_descriptors[(fd, cr3)].is_fake

# Need to initialize PANDA object before registering callback fns
if __name__ == '__main__':
    arch = "x86_64"
    panda = Panda(generic=arch)
    panda.set_os_name("linux-64-ubuntu")

    panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
    panda.require("syscalls2")

# Read: If we're reading from a FD in fake_files, return fake data
cb_name = "on_sys_read_return"
cb_args = "CPUState *, target_ulong, uint32_t, uint64_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ppp("syscalls2", f"ppp_add_cb_{cb_name}")
@ffi.callback(f"void({cb_args})")
def on_sys_read_return(cpu, pc, fd, buf, count):
    cr3 = cpu.env_ptr.cr[3]
    if is_hooked(fd, cr3):
        # We need to make up a file. Grab our contents/fn
        f = file_descriptors[(fd, cr3)]
        assert(f.is_fake), "Can't fake a non-faked FD"
        faker = files_faked[f.filename]
        logger.info(f"Hooking return of read for FD={fd} corresponding to file {f.filename}")
        if faker.fake_contents: # Static file contents
                # index into it based on f.offset return up to count
            contents = faker.fake_contents
            if f.first_read: # First read, don't set buffer, just return total size
                logger.info(f"\t returning buffer size ({len(contents)})")
                cpu.env_ptr.regs[R_EAX] = len(contents)
                f.first_read = False
            elif f.offset >= len(contents):  # No bytes left to read
                logger.info(f"\t Returning EOF")
                cpu.env_ptr.regs[R_EAX] = 0
                return
            else: # Bytes to read
                file_contents = contents[f.offset:f.offset+count].encode("utf8")
                logger.info(f"\t Set buffer at 0x{buf:x} to: {file_contents}")
                panda.virtual_memory_write(cpu, buf, file_contents) # Write buffer
                cpu.env_ptr.regs[R_EAX] = len(file_contents) # Bytes written
                f.offset += len(file_contents)
                return

        else: # Function
            fn = faker.faking_fn
            # Function returns data to write into buf, new offset, and what to return to guest
            (data, new_offset, ret_val) = fn(f.offset, cnt)
            if data and len(data):
                panda.virtual_memory_write(cpu, buf, data)
            f.offset = new_offset

            cpu.env_ptr.regs[R_EAX] = ret_val


# Close: If we close a FD in fake_files, fake the close and update fake_files to be closed
cb_name = "on_sys_close_return"
cb_args = "CPUState *, target_ulong, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ppp("syscalls2", f"ppp_add_cb_{cb_name}")
@ffi.callback(f"void({cb_args})")
def on_sys_close_return(cpustate, pc, fd):
    cr3 = cpustate.env_ptr.cr[3]
    if is_hooked(fd, cr3):
        logger.info(f"Hooking return of close for FD={fd}")
        cpustate.env_ptr.regs[R_EAX] = 0  # hide error
        del file_descriptors[(fd, cr3)]

# Open: Update file_descriptors. If it's a file we want to fake,
# generate a new FD and update file_descriptors
# If it's a file we aren't faking, assert if it collides with one of our FDs
cb_name = "on_sys_open_return"
cb_args = "CPUState *, target_ulong, uint64_t, int32_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ppp("syscalls2", f"ppp_add_cb_{cb_name}")
@ffi.callback(f"void({cb_args})")
def on_sys_open_return(cpustate, pc, filename, flags, mode):
    cr3 = cpustate.env_ptr.cr[3]
    fname = panda.virtual_memory_read(cpustate, filename, 255, fmt='str').decode('utf8')

    for hooked_fname in files_faked:
        if hooked_fname.match(fname):
            break
    else:
        # No hooked filenames matched, it's a normal guest file, just track FD use
        fd = cpustate.env_ptr.regs[R_EAX]
        file_descriptors[(fd, cr3)] = HyperFile(fname)
        return

    # A filename matched (hooked_fnam)
    logger.info(f"Hooking return of open for filename={fname}")

    # Generate a new FD that's unused. Don't go below 100 to avoid
    # FDs in use before we started tracking. Might be able to go higher
    for fd in range(255, 100, -1):
        if (fd, cr3) not in file_descriptors:
            break
    else:
        raise RuntimeError("No available FDs to fake")
    
    #only if cpustate.env_ptr.regs[R_EAX] > 255: because some hack for -1?
    file_descriptors[(fd, cr3)] = HyperFile(hooked_fname, True, 0)
    cpustate.env_ptr.regs[R_EAX] = fd

# fstat: Silence errors on our FD - Should probably also populate a stat object

# Unnecessary but useful if we want to mess with stat data structure?
# Hand made for CFFI but I guess it's unnecessary. Could remove
stat_h = """typedef struct stat {
    // Assuming long is 8, int is 4
    long st_dev;		/* Device.  */
    long st_ino;		/* File serial number.	*/
    long st_nlink;		/* Link count.  */
    int st_mode;		/* File mode.  */
    int st_uid;		/* User ID of the file's owner.	*/
    int st_gid;		/* Group ID of the file's group.*/
    int __pad0;
    long st_rdev;		/* Device number, if device.  */
    long st_size;			/* Size of file, in bytes.  */
    long st_blksize;	/* Optimal block size for I/O.  */
    //char st_atim[10];
    char st_mtim[10];
    char st_ctim[10];
  } stat;
"""

# XXX just the useful fields
stat_h = """typedef struct stat {
    // Assuming long is 8, int is 4
    long st_dev;		/* Device.  */
    long st_ino;		/* File serial number.	*/
    long st_nlink;		/* Link count.  */
    int st_mode;		/* File mode.  */
    int st_uid;		/* User ID of the file's owner.	*/
    int st_gid;		/* Group ID of the file's group.*/
    int __pad0;
    long st_rdev;		/* Device number, if device.  */
    long st_size;			/* Size of file, in bytes.  */
    long st_blksize;	/* Optimal block size for I/O.  */
} stat;
""";
ffi.cdef(stat_h)

# Example normal file:
# st_dev=makedev(252, 0),
# st_ino=3146445,
# st_mode=S_IFREG|0664,
# st_nlink=1,
# st_uid=1001, st_gid=1001,
# st_blksize=4096, st_blocks=8, st_size=7,
        
cb_name = "on_sys_newfstat_return"
cb_args = "CPUState *, target_ulong, uint32_t, uint64_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ppp("syscalls2", f"ppp_add_cb_{cb_name}")
@ffi.callback(f"void({cb_args})")
def on_sys_newfstat_return(cpustate, pc, fd, stat_ptr):
    cr3 = cpustate.env_ptr.cr[3]
    if is_hooked(fd, cr3):
        logger.info(f"Hooking return of newfstat for FD={fd}")
        # Mutate the stat buffer to set a size and hide errors

        # Read the object from guest memory into a cffi mutable struct
        # note that mutating c_stat affects the same memory as python_stat
        python_stat = panda.virtual_memory_read(cpustate, stat_ptr, ffi.sizeof("stat"))
        c_stat = ffi.from_buffer('stat*', python_stat) # XXX: setting require_writable fails
                                                    # but this is giving us a mutable buffer
        # Mutate it
        c_stat.st_ino = random.randint(100000, 1000000)
        c_stat.st_size = files_faked[file_descriptors[(fd, cr3)].filename].get_size(8)
        c_stat.st_blksize = 8

        # Put it back into guest memory
        panda.virtual_memory_write(cpustate, stat_ptr, python_stat)
        cpustate.env_ptr.regs[R_EAX] = 0 # No error

# fadvise64 - Strace shows it's unhappy but it doesn't affect output so maybe we ignore it?
'''
cb_name = "on_sys_fadvise64_return"
cb_args = "CPUState *, target_ulong, uint32_t, uint32_t, uint32_t"
ffi.cdef(f"void ppp_add_cb_{cb_name}(void (*)({cb_args}));")

@ppp("syscalls2", f"ppp_add_cb_{cb_name}") # Runs after our named CB
@ffi.callback(f"void({cb_args})")
def on_fadvise(cpustate, pc, fd, a, flags):
    pass
'''

if __name__== '__main__':
    # Test: Run something in the guest that reads from a fake file
    @blocking
    def mycmd():
        panda.revert_sync("root")
        cmd = "cat /dev/panda /manda"
        #panda.revert_sync("strace")
        #cmd = "strace -v cat /dev/panda /manda"
        print(f"GUEST RUNNING COMMAND:\n\n# {cmd}\n" + panda.run_serial_cmd(cmd))
        panda.end_analysis()

    add_file("*panda", "hello world I'm a panda\n")
    add_file("*manda", "SECOND PANDA\n")

    panda.queue_async(mycmd)
    panda.run()

