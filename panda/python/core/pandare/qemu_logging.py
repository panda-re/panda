class QEMU_Log_Manager:
    '''
    QEMU_Log_Manager

    This class manages the QEMU log. It does so by manipulating two key QEMU
    variables:
    - qemu_loglevel: int mask of the log levels to be logged
    - qemu_logfile: FILE* to the log file


    This class generates methods for manipulating the log level of the form:
    - [MEMBER_NAME]_enable()
    - [MEMBER_NAME]_disable()

    It provides an equivalent method for setting the log file of the form:
    - enable("[MEMBER_NAME]")
    - disable("[MEMBER_NAME]")

    It also provides methods for setting a file to log to and a method to remove
    the current log file.
    
    The following log types are supported:
    
        - TB_OUT_ASM
        - TB_IN_ASM
        - TB_OP,
        - TB_OP_OPT
        - INT
        - EXEC
        - PCALL
        - TB_CPU
        - RESET
        - UNIMP
        - GUEST_ERROR
        - MMU
        - TB_NOCHAIN
        - PAGE
        - TRACE
        - TB_OP_IND
        - TAINT_OPS
        - RR
        - LLVM_IR
        - LLVM_ASM

    '''
    def __init__(self, panda):
        self.panda = panda

        log_members = {
            "TB_OUT_ASM": 0,
            "TB_IN_ASM": 1,
            "TB_OP": 2,
            "TB_OP_OPT": 3,
            "INT": 4,
            "EXEC": 5,
            "PCALL": 6,
            "TB_CPU": 8,
            "RESET": 9,
            "UNIMP":10,
            "GUEST_ERROR":11,
            "MMU":12,
            "TB_NOCHAIN":13,
            "PAGE":14,
            "TRACE":15,
            "TB_OP_IND":16,
            "TAINT_OPS":28,
            "RR":29,
            "LLVM_IR":30,
            "LLVM_ASM":31,
        }
        self.log_members = log_members

        def setup_member(member):
            def enable():
                self.panda.libpanda.qemu_loglevel |= (1 << log_members[member])
            def disable():
                self.panda.libpanda.qemu_loglevel &= ~(1 << log_members[member])
            name = member.lower()
            setattr(self, name + "_enable", enable)
            setattr(self, name + "_disable", disable)

        for member in log_members:
            setup_member(member)
    
    def enable(self, name):
        """Enables the specified log level.

        Args:
            name (str): name of the log type (for list -d ?)

        Raises:
            Exception: no such log member
        """
        if name.upper() in self.log_members:
            self.panda.libpanda.qemu_loglevel |= (1 << self.log_members[name.upper()])
        else:
            raise Exception("no such log member: " + name)
    
    def disable(self, name):
        """Disables the specified log level.

        Args:
            name (str): name of log type (for list -d ?)

        Raises:
            Exception: no such log member
        """
        if name.upper() in self.log_members:
            self.panda.libpanda.qemu_loglevel &= ~(1 << self.log_members[name.upper()])
        else:
            raise Exception("no such log member: " + name)

    
    def output_to_file(self, file_name, append=True):
        """Change qemu log file to file_name. If append is True, output will
        be appended to the file. Otherwise, the file will be overwritten.

        Args:
            file_name ([str]): path to the file to output to
            append (bool, optional): File append setting
        """
        # qemu_logfile out previous file (if any)
        self.remove_log_file()

        # open new file
        mode = b"a" if append else b"w"
        self.panda.libpanda.qemu_logfile = self.panda.libpanda.fopen(file_name.encode(),  mode)
        
    def remove_log_file(self):
        """Removes the current log file. By default outputs to stdout."""
        if self.panda.libpanda.qemu_logfile != self.panda.ffi.NULL:
            # dont close stderr
            if self.panda.libpanda.fileno(self.panda.libpanda.qemu_logfile) != 2:
                self.panda.libpanda.fclose(self.panda.libpanda.qemu_logfile)
            self.panda.libpanda.qemu_logfile = self.panda.ffi.NULL
    
    def output_to_stdout(self):
        """Removes the current log file and outputs to stdout"""
        self.remove_log_file()



