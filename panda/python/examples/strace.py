'''
This is an example of building a pypanda plugin class to do analysis with PANDA. To see
how it's used look at pypanda_plugin_user.py
'''

from pandare import PyPlugin

class Strace(PyPlugin):
    def enter_cb(self, syscall_name, fname_ptr_pos, **kwargs):
        cpu=kwargs['args'][0]
        pcu=kwargs['args'][1]
        fname_ptr=kwargs['args'][2+fname_ptr_pos] # offset to after (cpu, pc) in callback args
        try:
            fname = self.panda.read_str(cpu, fname_ptr)
        except ValueError:
            fname = "(error)"
        print(f"Entering {syscall_name} {fname}")


    def return_cb(self, syscall_name, fname_ptr_pos, **kwargs):
        cpu=kwargs['args'][0]
        pcu=kwargs['args'][1]
        fname_ptr=kwargs['args'][2+fname_ptr_pos] # offset to after (cpu, pc)
        try:
            fname = self.panda.read_str(cpu, fname_ptr)
        except ValueError:
            fname = "(error)"
        print(f"Returning from {syscall_name} {fname}")

    def gen_cb(self, name, fname_ptr_pos):
        self.panda.ppp("syscalls2", f"on_sys_{name}_enter")( \
                    lambda *args: self.enter_cb(name, fname_ptr_pos, args=args))

        self.panda.ppp("syscalls2", f"on_sys_{name}_return")( \
                    lambda *args: self.return_cb(name, fname_ptr_pos, args=args))

    def __init__(self, panda):
        self.panda = panda

        # Syscalls that have char *fname as the 1st argument
        for name in ["chdir", "mknod", "chmod",  "chroot",
                     "newstat",  "lchown", "chown",  "access",
                     "statfs", "newstat", "newlstat", "utime", "utimes"]:
            self.gen_cb(name, 0)
        
        if panda.bits == 32:
            for name in ["chown16","lchown16", "stat64", "lstat64"]:
                self.gen_cb(name, 0)

        # Syscalls that have char *fname as the 2nd argument
        for name in ["openat", "mknodat", "fchownat", "futimesat", "fchmodat",
                "faccessat", "utimensat", "execveat"]:
            self.gen_cb(name, 1)
        
        if panda.bits == 32:
            for name in ["fstatat64"]:
                self.gen_cb(name, 1)
