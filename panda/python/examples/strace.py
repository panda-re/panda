class Strace:
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
        panda.load_plugin("syscalls2")

        # Syscalls that have char *fname as the 1st argument
        for name in ["chdir", "mknod", "chmod", "lchown16", "utime", "chroot",
                     "newstat", "chown16", "lchown", "chown", "utimes", "access",
                     "statfs", "newstat", "newlstat", "stat64", "lstat64"]:
            self.gen_cb(name, 0)

        # Syscalls that have char *fname as the 2nd argument
        for name in ["openat", "mknodat", "fchownat", "futimesat", "fchmodat",
                "faccessat", "utimensat", "execveat", "fstatat64"]:
            self.gen_cb(name, 1)
