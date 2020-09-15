"""
Framework for halucinating files inside the guest through
modifications around syscalls involving filenames and file
descriptors.

High-level idea:
    When we see an open of a file we want to fake, change it to another filename
    that really exists and capture the file descriptor assigned to it.
    Then whenever there are uses of that file descriptor, ignore/drop the request
    and fake return values.
"""


from panda.extras.file_hook import FileHook
from panda.ffi_importer import ffi
import logging


class FakeFile:
    '''
    A fake file behind a hyperFD - this class will generate data when the
    corresponding file descriptor(s) are accessed.
    Users can inherit and modify this to customize how data is generated

    Note: a single FileFaker might be opened and in use by multiple FDs in the guest

    '''
    def __init__(self, fake_contents="", filename=None):
        self.logger = logging.getLogger('panda.hooking')

        if isinstance(fake_contents, str):
            fake_contents = fake_contents.encode("utf8")
        fake_contents += b'\x00'
        self.contents = fake_contents
        self.initial_contents = fake_contents
        self.refcount = 0 # Reference count
        self.filename = filename # Just for debug printing

    def read(self, size, offset):
        '''
        Generate data for a given read of size.  Returns data.
        '''

        if offset >= len(self.contents):  # No bytes left to read
            return b""
        # Otherwise there are bytes left to read
        read_data = self.contents[offset:offset+size]

        return read_data

    def write(self, offset, write_data):
        '''
        Update contents from offset. It's a bytearray so we can't just mutate
        Return how much HyperFD offset should be incremented by
        XXX what about writes past end of the file?
        '''
        self.logger.info("FakeFD({self.filename}) writing {new_data} at offset {self.offset}")
        new_data  = self.contents[:offset]
        new_data += write_data
        new_data += self.contents[offset+len(new_data):]

        self.contents = new_data
        return len(write_data)

    def close(self):
        self.refcount -= 1
        if self.refcount == 0: # All FDs are now closed
            if self.initial_contents == self.contents:
                self.logger.debug(f"All handles to Faker({self.filename}) closed. Unmodified contents")
            else: # it was mutated!
                self.logger.info(f"All handles to Faker({self.filename}) closed. Modified contents: {repr(self.contents)}")

    def get_mode(self):
        return 0o664 # Regular file (octal)

    def get_size(self, bytesize):
        return ceil(len(self.contents)/bytesize)

    def __str__(self):
        return f"Faker({self.filename} -> {repr(self.contents[:10])}..."


    def _delete(self):
        self.close()

    def __del__(self):
        # XXX: This destructor isn't called automatically
        self._delete()

class HyperFD:
    '''
    A HyperFD is what we use to track the state of a faked FD in the guest.
    It is backed by a FakeFile.
    Stores the filename originally associated with it at time of open
    '''
    def __init__(self,  filename, fakefile, offset=0):
        self.name = filename
        self.file = fakefile
        self.file.refcount+=1 # Count of open FDs pointing to the file
        self.offset = offset

    def read(self, size):
        '''
        Read from the file descriptor. Determine current offset
        and then pass request through to FakeFile
        Returns (data read, count)
        '''
        assert(self.file)
        data = self.file.read(size, self.offset)
        self.offset+=len(data)
        return (data, len(data))

    def write(self, data):
        assert(self.file)
        bytes_written =  self.file.write(self.offset, data)
        self.offset +- bytes_written
        return bytes_written

    def get_mode(self):
        assert(self.file)
        return self.file.get_mode()

    def get_size(self):
        assert(self.file)
        return self.file.get_mode()

    def close(self):
        '''
        Decrement the reference counter
        '''
        assert(self.file)
        self.file.close()
        #del self # ???

    def seek(self, offset, whence):
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
            raise ValueError(f"Unsupported whence {whence} in seek")

    def __str__(self):
        return f"HyperFD with name {self.name} offset {self.offset} backed by {self.file}"


class FileFaker(FileHook):
    '''
    Class to halucinate fake files within the guest. When the guest attempts to access a faked file,
    we transparenly redirect the access to another file on disk and grab the FD generated using FileHook.

    When the guest attempts to use a FD related to a faked file, we mutate the request. Reads are created
    from fake conents and writes are logged.
    '''

    def __init__(self, panda):
        '''
        Initialize FileHook and vars. Setup callbacks for all fd-based syscalls
        '''
        super().__init__(panda)

        self.faked_files = {} # filename: Fake
        self.hooked_fds = {} # (fd, cr3): HyperFD->faker
        self.currently_hooked = None # fd, asid tuple. Set when we're entering a syscall to hook. cleared on return
        self.pending_hfd = None

        to_hook = {} # index of fd argument: list of names
        if panda.arch == "i386":
            # grep 'int fd' syscall_switch_enter_linux_x86.cpp  | grep "\['int fd\|\['unsigned int fd" | grep -o sys_[a-zA-Z0-9_]* | sed -n -e 's/sys_\(.*\)/"\1" /p' | paste -sd "," -
            # Note the grep commands missed dup2 and dup3 which take oldfd as 1st arg
            to_hook[0] = ["read", "write", "close", "lseek", "fstat", "ioctl", "fcntl", "ftruncate", "fchmod",
                          "fchown16", "fstatfs", "newfstat", "fsync", "fchdir", "llseek", "getdents", "flock",
                          "fdatasync", "pread64", "pwrite64", "ftruncate64", "fchown", "getdents64", "fcntl64",
                          "readahead", "fsetxattr", "fgetxattr", "flistxattr", "fremovexattr", "fadvise64",
                          "fstatfs64", "fadvise64_64", "inotify_add_watch", "inotify_rm_watch", "splice",
                          "sync_file_range", "tee", "vmsplice", "fallocate", "recvmmsg", "syncfs", "sendmmsg",
                          "setns", "finit_module", "getsockopt", "setsockopt", "sendmsg", "recvmsg", "dup2",
                          "dup3" ]

            # grep 'int fd' syscall_switch_enter_linux_x86.cpp  | grep -v "\['int fd\|\['unsigned int fd" # + manual
            to_hook[2] = ["epoll_ctl"]
            to_hook[3] = ["fanotify_mark"]

        elif panda.arch == "x86_64":
            to_hook[0] = ["read", "write", "close", "newfstat", "lseek", "ioctl", "pread64", "pwrite64", "sendmsg",
                          "recvmsg", "setsockopt", "getsockopt", "fcntl", "flock", "fsync", "fdatasync", "ftruncate",
                          "getdents", "fchdir", "fchmod", "fchown", "fstatfs", "readahead", "fsetxattr", "fgetxattr",
                          "flistxattr", "fremovexattr", "getdents64", "fadvise64", "inotify_add_watch",
                          "inotify_rm_watch", "splice", "tee", "sync_file_range", "vmsplice", "fallocate", "recvmmsg",
                          "syncfs", "sendmmsg", "setns", "finit_module", "copy_file_range", "dup2", "dup3"]
            to_hook[2] = ["epoll_ctl"]
            to_hook[3] = ["fanotify_mark"]

        elif panda.arch == "arm":
            to_hook[0] = ["read", "write", "close", "lseek", "ioctl", "fcntl", "ftruncate", "fchmod", "fchown16",
                          "fstatfs", "newfstat", "fsync", "fchdir", "llseek", "getdents", "flock", "fdatasync",
                          "pread64", "pwrite64", "ftruncate64", "fchown", "getdents64", "fcntl64", "readahead",
                          "fsetxattr", "fgetxattr", "flistxattr", "fremovexattr", "fstatfs64", "arm_fadvise64_64",
                          "setsockopt", "getsockopt", "sendmsg", "recvmsg", "inotify_add_watch", "inotify_rm_watch",
                          "splice", "sync_file_range2", "tee", "vmsplice", "fallocate", "recvmmsg", "syncfs",
                          "sendmmsg", "setns", "finit_module", "dup2", "dup3"]
            to_hook[2] = ["epoll_ctl"]
            to_hook[3] = ["fanotify_mark"]
        else:
            raise ValueError(f"Unsupported PANDA arch: {panda.arch}")

        for arg_offset, names in to_hook.items():
            for name in names:
                self._gen_fd_cb(name, arg_offset)

    def replace_file(self, filename, faker):
        '''
        Replace all accesses to filename with accesses to the fake file instead
        '''
        self.faked_files[filename] = faker

        # XXX: We rename the files to real files to the guest kernel can manage FDs for us.
        #      this may need to use different real files depending on permissions requested
        self.rename_file(filename, "/etc/passwd")

    def _gen_fd_cb(self, name, fd_offset):
        '''
        Register syscalls2 PPP callback on enter and return for the given name
        which has an argument of fd at fd_offset in the argument list
        '''
        self._panda.ppp("syscalls2", f"on_sys_{name}_enter", name=f"file_faker_enter_{name}")( \
                    lambda *args: self._enter_fd_cb(name, fd_offset, args=args))
        self._panda.ppp("syscalls2", f"on_sys_{name}_return", name=f"file_faker_return_{name}")( \
                    lambda *args: self._return_fd_cb(name, fd_offset, args=args))

    def _enter_fd_cb(self, syscall_name, fd_pos, args=None):
        '''
        When we're about to enter a callback. Check if the fd is hooked and if so
        update currently_hooked so we can fix it upon return.
        Maybe this could be updated to skip the hooked syscalls entirely?
        '''
        assert(args)
        (cpu, pc) = args[0:2]
        fd = args[2+fd_pos]
        asid = self._panda.current_asid(cpu)

        if fd == 0xffffffff:
            self.logger.debug(f"Got -1 for fd in enter of {syscall_name}")
            return

        assert(fd < 0xffffffff), "FD overflow?"

        # Looks like this file isn't hooked. Let's use OSI and confirm
        if (fd, asid) not in self.hooked_fds:
            # Let's use OSI to figure out the backing filename here
            fname = self._get_fname(cpu, fd)
            if fname and fname in self.faked_files:
                self.logger.warning("Entering {syscall_name} with fd {fd} backed by {fname} but we missed it earlier - adding it now")
                hfd = HyperFD(fname, self.faked_files[fname]) # Create HFD
                self.hooked_fds[(fd, asid)] =  hfd

        # If this file descriptor is already hooked, update currently_hooked
        # so we know to mutate it when it returns
        if (fd, asid) in self.hooked_fds:
            hfd = self.hooked_fds[(fd, asid)]
            self.logger.info(f"Entering hooked syscall {syscall_name} for fd {fd}, " + \
                                f"filename {hfd.name}")
            self.currently_hooked = (fd, asid)


    def _return_fd_cb(self, syscall_name, fd_pos, args=None):
        '''
        When we're returnuing from a syscall, mutate memory
        to put the results we want there
        '''
        if not self.currently_hooked:
            return

        (fd, asid) = self.currently_hooked
        hfd = self.hooked_fds[(fd, asid)]

        self.currently_hooked = None
        assert(args)

        (cpu, pc) = args[0:2]
        fd = args[2+fd_pos]
        asid = self._panda.current_asid(cpu)

        if syscall_name == "read":
            self.logger.debug(f"Handling READ of fakeFD {fd} {hfd.name}")
            # Place up to `count` bytes of data into memory at `buf_ptr`
            buf_ptr = args[3]
            count   = args[4]

            (data, data_len) = hfd.read(count)
            if data:
                try:
                    self._panda.virtual_memory_write(cpu, buf_ptr, data)
                except ValueError:
                    self.logger.error(f"Unable to store fake data after read to {hfd}")
                    return

            cpu.env_ptr.regs[0] = data_len

            #self.logger.info(f"Returning {data_len} bytes")

        elif syscall_name == "close":
            # We want the guest to close the real FD. Delete it from our map of hooked fds
            hfd.close()
            if (fd, asid) in self.hooked_fds:
                del self.hooked_fds[(fd, asid)]

        elif syscall_name == "write":
            # read count bytes from buf, add to our hyper-fd
            buf_ptr = args[3]
            count   = args[4]
            try:
                data = self._panda.virtual_memory_read(cpu, buf_ptr, count)
            except ValueError:
                self.logger.error(f"Unable to read buffer that was being written")
                return

            bytes_written = hfd.write(data)
            cpu.env_ptr.regs[0] = bytes_written

        elif syscall_name == "lseek": # LLSEEK?
            offset = args[2]
            whence = args[3]
            hfd.seek(offset, whence)


        elif syscall_name in ["dup2", "dup3"]:
            # add newfd
            oldfd = args[2]
            newfd = args[3]
            self.logger.debug(f"Duplicating faked fd {oldfd} to {newfd}")

            # Duplicate the old hfd - but not the file behind it
            new_hfd = HyperFD(hfd.name, hfd.file, hfd.offset)
            self.hooked_fds[(newfd, asid)] = new_hfd

        else:
            self.logger.error(f"Unsupported syscall on FakeFD{fd}: {syscall_name}. Not intercepting (Running on real guest FD)")


    def _before_modified_enter(self, cpu, pc, syscall_name, fname):
        '''
        Overload FileHook function. Determine if a syscall we're about to
        enter is using a filename we want to fake

        After the modified syscall returns, we grab the real FD and map it to the HFD
        '''
        if fname in self.faked_files:
            self.pending_hfd =  HyperFD(fname, self.faked_files[fname]) # Create HFD
            asid = self._panda.current_asid(cpu)

    def _after_modified_return(self, cpu, pc, syscall_name):
        '''
        Overload FileHook function. Determine if a syscall we're about to
        return from was using a filename we want to fake. If so, grab the FD
        '''
        if self.pending_hfd:
            # XXX: is asid correct here?
            fd = cpu.env_ptr.regs[0] # XXX: definitely isn't true for all syscalls
            asid = self._panda.current_asid(cpu)
            self.hooked_fds[(fd, asid)] =  self.pending_hfd
            self.pending_hfd = None


    def close(self):
        # Close all open hfds
        if len(self.hooked_fds):
            self.logger.debug("Cleaning up open hyper file descriptors")
            for (fd, asid) in list(self.hooked_fds.keys()):
                self.hooked_fds[(fd, asid)].close()
                del self.hooked_fds[(fd, asid)]


    def __del__(self):
        # XXX: This isn't being called for some reason on destruction
        self.close()
