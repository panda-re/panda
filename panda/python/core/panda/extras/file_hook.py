import logging
from os import path
from panda.x86.helper import dump_state

# If coloredlogs is installed, use it
try:
    import coloredlogs
    import sys
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)
except ImportError:
    pass
# End temp

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
        (from all syscalls that have a char* filename argument.
        '''

        self.logger = logging.getLogger('panda.hooking')
        self.logger.setLevel(logging.DEBUG)

        self._panda = panda
        self._renamed_files = {} # old_fname (str): new_fname (bytes)
        self._awaiting_pointers = {} # ASID: fname we want to read
        self._current_fname = {} # ASID: current filename
        self._old_data = {} # ASID: old data we clobbered
        self._current_syscall = {} # ASID: syscall name

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

        # Note this function is defined in __init__ when panda is available
        @panda.cb_virt_mem_before_read(enabled=False)
        def _file_hook_before_read(cpu, pc, addr, size):
            '''
            Fallback, slow-path for when the fname ptr is paged out when we enter a syscall.
            Before the guest does a virtual memory read - If it's an ASID
            that we're currently trying to load a filename pointer from virtual memory,
            try loading it if the current read is within 0x1k of our address.
            If it works, run mutate_filename BEFORE the guest code has a chance to read
            '''

            asid = self._panda.current_asid(cpu)
            try:
                target = self._awaiting_pointers[asid]
            except KeyError: # Don't need anything from this process
                self._panda.disable_callback('_file_hook_before_read')
                return

            if abs(addr-target) <  0x1000:
                # If the current read is an address close to what we want, try to read it
                try:
                    fname = self._panda.read_str(cpu, self._awaiting_pointers[asid])
                except ValueError:
                    return

                # Successful read! Need to mutate it in guest memory
                self._current_fname[asid] = fname
                logger.debug(f"read pending string for 0x{asid:x}: {fname}")
                self.mutate_if_necessary(cpu, self._current_syscall[asid], fname, self._awaiting_pointers[asid])
                self.logger.info("Removing asid 0x{asid:x} fname 0x{fname_ptr:x}={fname} from awaiting pointers")
                del self._awaiting_pointers[asid] # done with it
                self._panda.disable_callback('_file_hook_before_read') # Will be re-enabled if necessary when we switch to another asid

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

    def _enter_cb(self, syscall_name, fname_ptr_pos=0, args=None, fname_ptr=None):
        '''
        When we return, check if we mutated the fname buffer. If so,
        we need to restore whatever data was there (we may have written
        past the end of the string).

        if fname_ptr is set, just skip the logic to extract it
        '''

        assert(args)
        (cpu, pc) = args[0:2]
        asid = self._panda.current_asid(cpu)

        fname_ptr = args[2+fname_ptr_pos] # after cpu, pc,
        self._current_syscall[asid] = syscall_name

        try:
            fname = self._panda.read_str(cpu, fname_ptr)
        except ValueError:
            if asid in self._awaiting_pointers:
                # This asid was ALREADY waiting for a different name- This doesn't really make sense but it _does_ happen.
                # If it's the same syscall name, let's assume an error was raised in the syscall execution and now it's being retried.
                # Otherwise, let's die
                if self._current_syscall[asid] == syscall_name:
                    self.logger.warning(f"Entered syscall {syscall_name} twice without returning")
                else:
                    self.logger.error(f"Was waiting on something but now another? Asid 0x{asid:x}. New syscall is {syscall_name}. Last was {self._current_syscall[asid]}")
                    assert(0), "The same ASID entered two syscalls without ever returning"
                    return

            self._awaiting_pointers[asid] = fname_ptr
            self.logger.debug(f"Adding asid 0x{asid:x} fname 0x{fname_ptr:x} to awaiting pointers")

            self._panda.enable_callback('_file_hook_before_read')
            return # Not gonna figure it out here

        # We know the filename. Great! Mutate if necessary
        self.mutate_if_necessary(cpu, syscall_name, fname, fname_ptr)


    def _return_cb(self, syscall_name, fname_ptr_pos, args=None):
        '''
        When we return, check if we mutated the fname buffer. If so,
        we need to restore whatever data was there (we may have written
        past the end of the string)
        '''
        assert(args)
        (cpu, pc) = args[0:2]
        asid = self._panda.current_asid(cpu)
        fname_ptr = args[2+fname_ptr_pos] # after cpu, pc,

        if asid not in self._current_fname:
            self.logger.error(f"Returning from syscall {syscall_name} but we never identified filename")
            return


        if asid in self._old_data: # Need to restore data we clobbered
            try:
                self._panda.virtual_memory_write(cpu, fname_ptr, self._old_data[asid])
            except ValueError:
                self.logger.error(f"Failed to restore filename buffer at return of {syscall_name}")
                return
            del self._old_data[asid]
            self._after_modified_return(cpu, pc, syscall_name)

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

    def mutate_if_necessary(self, cpu, syscall_name, fname, fname_ptr):
        '''
        Called as soon as we know the filename for a syscall we're entering.
        Should be run for every syscall which gives us a chance to mutate the fname
        Check if it's in our list of names to mutate
        '''

        # Normalize path and save by ASID
        fname = path.normpath(fname)
        asid = self._panda.current_asid(cpu)
        self._current_fname[asid] = fname

        if fname in self._renamed_files.keys():
            self.logger.debug(f"modifying filename {fname} in {syscall_name} to {self._renamed_files[fname]}")
            try:
                clobbering = self._panda.virtual_memory_read(cpu, fname_ptr, len(self._renamed_files[fname]))
            except ValueError:
                self.logger.error(f"Can't read clobbered data in {syscall_name}! Bailing") # Unlikely - we just read it
                return

            try:
                self._panda.virtual_memory_write(cpu, fname_ptr, self._renamed_files[fname])
            except ValueError:
                self.logger.error(f"Failed to mutate filename buffer at call into {syscall_name}")
                return

            # Save the data we overwrote
            self._old_data[asid] = clobbering

            pc = self._panda.current_pc(cpu)
            self._before_modified_enter(cpu, pc, syscall_name, fname)
