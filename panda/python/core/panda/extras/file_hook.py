import logging
# TEMP
import sys
root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)
import coloredlogs
coloredlogs.install()
#end temp

class FileHook:
    '''
    Class to modify guest memory just before syscalls with filename arguments.
    As the system call is about to be executed, change the data pointed to by the
    filename pointer. When the syscall returns, restore the mutated data to its
    original values.
    
    This provides a simple, cross-platform interface to redirect file accesses
    just using the OSI plugin.
    
    usage:
        from panda import Panda, extras
        panda = Panda(...)
        hook = extras.Hook(panda)
        hook.rename_file("/rename_this", "/to_this")
    '''

    def __init__(self, panda):
        '''
        Store a reference to the panda object, and register
        the appropriate syscalls2 callbacks for entering and exiting
        from all syscalls that have a char* filename argument.
        '''

        self._panda = panda
        self._renamed_files = {} # old_fname (str): new_fname (bytes)
        self._changed_strs = {} # callback_name: original_data

        self.logger = logging.getLogger('panda.hooking')
        self.logger.setLevel(logging.DEBUG)

        panda.load_plugin("syscalls2")

        # For each architecture, we have a different set of syscalls. They all
        # either call our functions with (cpu, pc, filename_ptr, ...)
        # or (cpu, pc, something_else, filename_ptr, ...). Here we 
        # Programmatically generate callbacks for all of them

        # These lists were made with commands like the following in syscalls2/generated:
        # grep filename syscall_switch_enter_linux_x86.cpp | grep "\['const char " | grep -o sys_[a-zA-Z0-9]* | grep -o [a-z0-9]*$
        # grep filename syscall_switch_enter_linux_x86.cpp | grep -v "\['const char " | grep -o sys_[a-zA-Z0-9]* | grep -o [a-z0-9]*$
        to_hook = {}
        if panda.arch == "i386":
            to_hook[0] = ["open", "execve", "chdir", "mknod", "chmod", "lchown16", "stat", "access", "chroot",
                         "lstat", "newstat", "newlstat", "chown16", "stat64", "lstat64", "lchown", "chown" ]
            to_hook[1] = ["utime", "utimes", "openat", "mknodat", "fchownat", "futimesat", "fstatat64",
                          "fchmodat", "faccessat", "utimensat", "execveat"]

        elif panda.arch == "x86_64":
            to_hook[0] = ["open", "newstat", "newlstat", "access", "chdir", "chmod", "chown", "lchown", "mknod", "chroot"]
            to_hook[1] = ["utime", "utimes", "openat", "mknodat", "fchownat", "futimesat", "newfstatat", "fchmodat", "faccessat", "utimensat"]

        elif panda.arch == "arm":
            to_hook[0] = ["open", "execve", "chdir", "mknod", "chmod", "lchown16", "access", "chroot", "newstat", "newlstat", "chown16", "stat64", "lstat64", "lchown", "chown"]
            to_hook[1] = ["utime", "utimes", "openat", "mknodat", "fchownat", "futimesat", "fstatat64", "fchmodat", "faccessat", "utimensat", "execveat"]
        else:
            raise ValueError(f"Unsupported PANDA arch: {panda.arch}")

        # Register the callbacks
        for arg_offset, names in to_hook.items():
            for name in names:
                self._gen_cb(name, arg_offset)

    def rename_file(self, old_name, new_name):
        '''
        Mutate a given filename into a new name at the syscall interface
        '''
        assert(old_name not in self._renamed_files), f"Already have a rename rule for {old_name}"

        if not isinstance(new_name, bytes):
            new_name = new_name.encode("utf8")

        if not new_name.endswith(b"\x00"):
            new_name += b"\x00"

        self._renamed_files[old_name] = new_name

    def _gen_cb(self, name, fname_ptr_pos):
        '''
        Register syscalls2 PPP callback on enter and return for the given name
        which has an argument of char* filename at fname_ptr_pos in the arguments list
        '''
        self._panda.ppp("syscalls2", f"on_sys_{name}_enter")( \
                    lambda *args: self._enter_cb(name, fname_ptr_pos, args=args))
        self._panda.ppp("syscalls2", f"on_sys_{name}_return")( \
                    lambda *args: self._return_cb(name, fname_ptr_pos, args=args))

    def _enter_cb(self, syscall_name, fname_ptr_pos, args=None):
        '''
        When we return, check if we mutated the fname buffer. If so,
        we need to restore whatever data was there (we may have written
        past the end of the string)
        '''
        assert(args)
        (cpu, pc) = args[0:2]
        fname_ptr = args[2+fname_ptr_pos] # offset to after (cpu, pc) in callback args

        try:
            fname = self._panda.read_str(cpu, fname_ptr)
        except ValueError:
            self.logger.warning(f"missed filename in call to {syscall_name}")
            return

        self.logger.debug(f"Entering {syscall_name} with file={fname}")

        if fname in self._renamed_files:
            # It matches, now let's take our action! Either rename or callback

            self.logger.info(f"Renaming {fname} in {syscall_name}  to {self._renamed_files[fname]}")
            assert(syscall_name not in self._changed_strs), "Entering syscall that already has a pending restore"

            # First read a buffer of the same size as our new value. XXX the string we already read might be shorter
            # than what we're inserting so we 
            try:
                clobbered_data = self._panda.virtual_memory_read(cpu, fname_ptr, len(self._renamed_files[fname]))
            except ValueError:
                self.logger.error(f"Failed to read target buffer at call into {syscall_name}")
                return

            # Now replace those bytes with our new name
            try:
                self._panda.virtual_memory_write(cpu, fname_ptr, self._renamed_files[fname])
            except ValueError:
                self.logger.warn(f"Failed to mutate filename buffer at call into {syscall_name}")
                return

            # If it all worked, save the clobbered data
            self._changed_strs[syscall_name] = clobbered_data

            self._before_modified_enter(cpu, pc, syscall_name, fname)


    def _return_cb(self, syscall_name, fname_ptr_pos, args=None):
        '''
        When we return, check if we mutated the fname buffer. If so,
        we need to restore whatever data was there (we may have written
        past the end of the string)
        '''
        if syscall_name in self._changed_strs:
            assert(args)
            (cpu, pc) = args[0:2]
            fname_ptr = args[2+fname_ptr_pos] # offset to after (cpu, pc) in callback args
            try:
                self._panda.virtual_memory_write(cpu, fname_ptr, self._changed_strs[syscall_name])
            except ValueError:
                self.logger.warn(f"Failed to fix filename buffer at return of {syscall_name}")
            del self._changed_strs[syscall_name]
            self._after_modified_return(cpu, pc, syscall_name)

        self.logger.debug(f"Returning from {syscall_name}")

    def _before_modified_enter(self, cpu, pc, syscall_name, fname):
        '''
        Internal callback run before we enter a syscall where we mutated
        the filename. Exists to be overloaded by subclasses
        '''
        pass

    def _after_modified_return(self, cpu, pc, syscall_name):
        '''
        Internal callback run before we return from a syscall where we mutated
        the filename. Exists to be overloaded by subclasses
        '''
        pass
