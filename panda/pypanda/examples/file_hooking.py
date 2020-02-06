#!/usr/bin/env python3

# Fake files from the hypervisor

# When we get an open to a file of interest, change syscall into kernel to make it open another file
# Whenever that file is read/written to, intercept and just log
# When that FD is dup'd taint the new FD and intercept as well

from sys import argv, stdout
from os import path
import enum
import re
import random
from math import ceil
from panda import Panda, blocking, ffi
from panda.x86.helper import * # XXX omg these are 32-bit names

import logging

logging.basicConfig(level = logging.INFO)
logger = logging.getLogger('panda.file_hooking')
logger.setLevel(logging.INFO)

# Classes for tracking faked files by name and FD
class FakedFile:
    '''
    A class to generate data when a fake file is read
    Inherit and modifiy methods to customize
    Note that a single FakedFile might be opened and in use by multiple FDs in the guest
    '''
    def __init__(self, fake_contents=""):
        self.data = fake_contents

    def get_data(self, fd, size):
        '''
        Generate data for a given HyperFile of size
        '''
        contents = self.data
        if isinstance(contents, str):
            contents = contents.encode("utf8")
        contents += b'\x00'

        if fd.offset >= len(contents):  # No bytes left to read
            logger.debug(f"\t Returning EOF")
            return (None, 0)
        # Otherwise there are bytes left to read
        file_contents = contents[fd.offset:fd.offset+size]
        fd.offset += len(contents)

        return (file_contents,        # Data to write into fd
                len(file_contents))   # Num bytes read


    def get_mode(self):
        return 0o664 # Regular file (octal)

    def get_size(self, bytesize):
        return ceil(len(self.data)/bytesize)

class HyperFile:
    '''
    The data behind a faked FD in the guest.
    Tracks offset and which filename (regex) rule that caused its creation
    '''
    def __init__(self,  filename, is_fake=False, offset=0):
        self.filename = filename
        self.is_fake = is_fake
        self.offset = offset

    def seek(offset, whence):
        # From include/uapi/linux/fs.h
        SEEK_SET = 0
        SEEK_CUR = 1
        SEEK_END = 2

        if whence == SEEK_SET:
            self.offset = offset
        elif whence == SEEK_CUR:
            self.offset = self.offset + offset
        elif whence == SEEK_END:
            self.offset = self.offset + offset
        else:
            raise ValueError("Unsupported whence {whence} in seek")


# To hook files we maintain two mappings
#   path regex -> fake contents OR faking fn
#       If multiple wildcards trigger, we just use the first
#   FDs -> [is_fake, file_offset]
#       file_offset is meaningless unless is_fake is True


files_faked = {} # name: (fake_contents, faking_fn)

file_descriptors = {} # (FD, CR3): HyperFile with filename set to a value from files_faked if fake


def add_file(name, faker):
    '''
    Register hooks for a file with a name that supports * for wildcards.
        Note that the guest may access files just by name without path.
        E.g., cd /dev; cat foo would just be triggered for name='foo', not
        '/dev/foo'

    faker should be a FakedFile/subclass object
    '''
    r_name = re.compile(name.replace("*", ".*"))
    files_faked[r_name] = faker

def is_hooked(fd, asid):
    return (fd, asid) in file_descriptors and file_descriptors[(fd, asid)].is_fake

# Need to initialize PANDA object before registering callback fns
if __name__ == '__main__':
    arch = "x86_64"
    panda = Panda(generic=arch)
    panda.set_os_name("linux-64-ubuntu")

    panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
    panda.require("syscalls2")

# Read: If we're reading from a FD in fake_files, return fake data
@panda.ppp("syscalls2", "on_sys_read_return")
def on_sys_read_return(cpu, pc, fd, buf, count):
    asid = panda.current_asid(cpu)
    if is_hooked(fd, asid):
        # We need to make up a file. Grab our contents/fn
        f = file_descriptors[(fd, asid)]
        assert(f.is_fake), "Can't fake a non-faked FD"
        faker = files_faked[f.filename]
        logger.debug(f"Hooking return of read for FD={fd} corresponding to file {f.filename}")
        """
        if faker.fake_contents: # Static file contents
                # index into it based on f.offset return up to count
            contents = faker.fake_contents+"\x00"
            if f.offset >= len(contents):  # No bytes left to read
                logger.debug(f"\t Returning EOF")
                cpu.env_ptr.regs[R_EAX] = 0
                return
            else: # Bytes to read
                file_contents = contents[f.offset:f.offset+count].encode("utf8")
                logger.debug(f"\t Set buffer at 0x{buf:x} to: {file_contents}")
                write_result = panda.virtual_memory_write(cpu, buf, file_contents) # Write buffer - May fail if page isn't mapped

                if write_result < 0: # Page not mapped. Make guest retry - Don't update our fake file's offset because this read will fail
                    logger.info(f"\t Failed to write data into guest memory")
                    cpu.env_ptr.regs[R_EAX] = ffi.cast("unsigned char", -11) # Return EAGAIN to make the guest retry (with page mapped, hopefully)
                    return
                cpu.env_ptr.regs[R_EAX] = len(file_contents) # Bytes written
                f.offset += len(file_contents)
                return

        else: # Function
        """

        # Write seems to be OK - call fn and update guest memory
        (data, ret_val) = faker.get_data(f, count)
        if data and len(data):
            write_result = panda.virtual_memory_write(cpu, buf, data)
            if write_result < 0: # Page not mapped. Make guest retry
                logger.info(f"\t Failed to write data into guest memory")
                cpu.env_ptr.regs[R_EAX] = ffi.cast("unsigned char", -11) # Return EAGAIN
                return

        cpu.env_ptr.regs[R_EAX] = ret_val

# Open: on enter, modify filename if we want to fake it. Then on return save FD
pending_hyperfile  = None
@panda.ppp("syscalls2", "on_sys_open_enter")
def on_sys_open_enter(cpu, pc, fname_ptr, flags, mode):
    global pending_hyperfile # Will be saved at return
    (fname, err) = panda.virtual_memory_read(cpu, fname_ptr, 100, fmt='str')
    if err != 0: # Leave pending_hyperfile = None so open_return will fail with EAGAIN
        return
    fname = fname.decode("utf8")
    for hooked_fname in files_faked:
        if hooked_fname.match(fname):
            break
    else:
        # No hooked filenames matched, it's a normal guest file, just track FD use
        pending_hyperfile = HyperFile(fname)
        return


    logger.info(f"Hooking open for filename={fname}")
    # It is hooked - Change the filename to something we know to exist
    # XXX XXX XXX: Must be shorter than original file name or we'll CORRUPT MEMORY
    # The root directory (is a file) should always satisfy these constraints
    # XXX: TODO no it won't - You can't write to it, the kernel knows it's a directory
    new_fname = b"/bin/ls\x00"
    r = panda.virtual_memory_write(cpu, fname_ptr, new_fname)
    assert(r >=0), "Failed to write new fname into memory"
    pending_hyperfile = HyperFile(hooked_fname, True)


@panda.ppp("syscalls2", "on_sys_open_return")
def on_sys_open_return(cpu, pc, fname_ptr, flags, mode):
    asid = panda.current_asid(cpu)
    fd = cpu.env_ptr.regs[R_EAX]
    global pending_hyperfile
    if not pending_hyperfile:
        # Return EAGAIN to make the guest retry (with page mapped, hopefully)
        cpu.env_ptr.regs[R_EAX] = ffi.cast("unsigned char", -11)
        return
    file_descriptors[(fd, asid)] = pending_hyperfile
    if pending_hyperfile.is_fake:
        logger.debug(f"Hook stored info for fake FD {fd} = {pending_hyperfile.filename}")
    pending_hyperfile = None

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
    char st_atim[10];
    char st_mtim[10];
    char st_ctim[10];
  } stat;
"""
ffi.cdef(stat_h)

# Example normal file:
# st_dev=makedev(252, 0),
# st_ino=3146445,
# st_mode=S_IFREG|0664,
# st_nlink=1,
# st_uid=1001, st_gid=1001,
# st_blksize=4096, st_blocks=8, st_size=7,

@panda.ppp("syscalls2", "on_sys_newfstat_return")
def on_sys_newfstat_return(cpu, pc, fd, stat_ptr):
    asid = panda.current_asid(cpu)
    if is_hooked(fd, asid):
        logger.debug(f"Hooking return of newfstat for FD={fd}")
        # Mutate the stat buffer to set a size and hide errors

        # Read the object from guest memory into a cffi mutable struct
        # note that mutating c_stat affects the same memory as python_stat
        (python_stat, err) = panda.virtual_memory_read(cpu, stat_ptr, ffi.sizeof("stat"))
        c_stat = ffi.from_buffer('stat*', python_stat) # XXX: setting require_writable fails
                                                    # but this is giving us a mutable buffer
        # Modify buffer - set a reasonable size given the FakedFile object
        thisFakeFile = files_faked[file_descriptors[(fd, asid)].filename]
        c_stat.st_ino = random.randint(0, 0xFFFFF)
        c_stat.st_mode = thisFakeFile.get_mode()
        c_stat.st_size = thisFakeFile.get_size(8)
        c_stat.st_blksize = 8

        # Put it back into guest memory
        r = panda.virtual_memory_write(cpu, stat_ptr, python_stat)
        assert(r >= 0), "Failed to write stat buffer"
        cpu.env_ptr.regs[R_EAX] = 0 # No error

# Write: on enter check if it's our target
@panda.ppp("syscalls2", "on_sys_write_enter")
def on_sys_write_enter(cpu, pc, fd, buf_ptr, count):
    asid = panda.current_asid(cpu)
    if is_hooked(fd, asid):
        cpu.env_ptr.regs[R_EAX] = 0xFF # Invalid FD - will make kernel return an error that
                                        # we'll hide. Prevents the write from really happening
        (buf, err) = panda.virtual_memory_read(cpu, buf_ptr, count)
        logger.info(f"Write {buf} to faked FD {fd}")

# Write return: Mask error
@panda.ppp("syscalls2", "on_sys_write_return")
def on_sys_write_return(cpu, pc, fd, buf, count):
    asid = panda.current_asid(cpu)
    if is_hooked(fd, asid):
        logger.debug(f"Hide error writing to FD {fd}")
        cpu.env_ptr.regs[R_EAX] = count # Pretend we wrote all bytes

@panda.ppp("syscalls2", "on_sys_dup2_enter")
def dup2_return(cpu, pc, oldfd, newfd):
    asid = panda.current_asid(cpu)
    if is_hooked(oldfd, asid):
        if cpu.env_ptr.regs[R_EAX] == newfd:
            logger.debug(f"DUP2 on a fake FD. Copy {oldfd} to {newfd}")
            assert((newfd, asid) not in file_descriptors), "DUP2 with a dest FD already used"
            file_descriptors[(newfd, asid)] = file_descriptors[(oldfd, asid)]

# Close: If it's a hooked FD, update file_descriptors and fake successful return
@panda.ppp("syscalls2", "on_sys_close_return")
def on_sys_close_return(cpu, pc, fd):
    asid = panda.current_asid(cpu)
    if is_hooked(fd, asid):
        logger.debug(f"Close of fd {fd}")
        del file_descriptors[(fd, asid)]
        cpu.env_ptr.regs[R_EAX] = 0 # No error

# lseek: If it's a hooked FD, seek it!
@panda.ppp("syscalls2", "on_sys_lseek_return")
def on_sys_lseek_return(cpu, pc, fd, offset, wence):
    asid = panda.current_asid(cpu)
    if is_hooked(fd, asid):
        logger.debug(f"Seek of hooked fd {fd}")
        file_descriptors[(fd, asid)].seek(offset, wence)
        cpu.env_ptr.regs[R_EAX] = 0 # No error



# fadvise64 - Strace shows it's unhappy but it doesn't affect output so maybe we ignore it?
#@panda.ppp("syscalls2", "on_sys_fadvise64_return"
def on_fadvise(cpu, pc, fd, a, flags):
    pass

# Debugging, catch all
#@panda.ppp("syscalls2", "on_all_sys_return")
def catch_all(cpu, pc, callno):
    print(f"Syscall {callno}")


if __name__== '__main__':
    # Test: Run something in the guest that reads from a fake file
    @blocking
    def mycmd():
        panda.revert_sync("root")
        cmd = "cat /dev/panda /testfile  /dev/panda"
        #panda.revert_sync("strace")
        #cmd = "strace /bin/sh -c 'cat /testfile > /dev/panda'"
        #cmd = "cat /testfile > /dev/panda"
        print(f"GUEST RUNNING COMMAND:\n\n# {cmd}\n" + panda.run_serial_cmd(cmd))
        panda.end_analysis()

    class DynamicFile(FakedFile):
        '''
        Class that halcuinates data. Simple example that shows
        returning hardcoded string in chunks of 4 characters
        that logs each time it's read
        '''
        def get_data(self, fd, size):
            size = 4 # Make guest read in chunks of 4
            print(f"TESTFILE CALLED: 0x{fd.offset:x}")
            data = f"TESTFILE read with offset = {fd.offset} and {fd.offset}\n"[fd.offset:fd.offset+size]
            data = data.encode("utf8")
            new_offset = max(fd.offset+size, len(data))
            fd.offset = new_offset
            return (data,         # Data to write into buffer (buffer)
                    len(data))    # Num bytes read
    
    static_file = FakedFile("hello world I'm a panda\n")
    dynamic_file = DynamicFile()

    add_file("*panda", static_file)
    add_file("*test", dynamic_file)

    panda.queue_async(mycmd)
    panda.run()

