'''
This module contains architecture-specific code.

When the `pandare.panda` class is initialized it will automatically
initialize a PandaArch class for the specified architecture in the variable
`panda.arch`.

'''
import binascii
from .utils import telescope

class PandaArch():
    '''
    Base class for architecture-specific implementations for PANDA-supported architectures
    '''
    def __init__(self, panda):
        '''
        Initialize a PANDA-supported architecture and hold a handle on the PANDA object
        '''
        self.panda = panda

        self.reg_sp      = None # Stack pointer register ID if stored in a register
        self.reg_pc      = None # PC register ID if stored in a register
        self.reg_retaddr = None # Register ID that contains return address
        self.reg_retval  = None # convention: register name that contains return val
        self.call_conventions = None # convention: ['reg_for_arg0', 'reg_for_arg1',...]
        self.registers = {}
        '''
        Mapping of register names to indices into the appropriate CPUState array
        '''

    def _determine_bits(self):
        '''
        Determine bits and endianness for the panda object's architecture
        '''
        bits = None
        endianness = None # String 'little' or 'big'
        if self.panda.arch_name == "i386":
            bits = 32
            endianness = "little"
        elif self.panda.arch_name == "x86_64":
            bits = 64
            endianness = "little"
        elif self.panda.arch_name == "arm":
            endianness = "little" # XXX add support for arm BE?
            bits = 32
        elif self.panda.arch_name == "aarch64":
            bits = 64
            endianness = "little" # XXX add support for arm BE?
        elif self.panda.arch_name == "ppc":
            bits = 32
            endianness = "big"
        elif self.panda.arch_name == "mips":
            bits = 32
            endianness = "big"
        elif self.panda.arch_name == "mipsel":
            bits = 32
            endianness = "little"

        assert (bits is not None), f"Missing num_bits logic for {self.panda.arch_name}"
        assert (endianness is not None), f"Missing endianness logic for {self.panda.arch_name}"
        register_size = int(bits/8)
        return bits, endianness, register_size

    def get_reg(self, cpu, reg):
        '''
        Return value in a `reg` which is either a register name or index (e.g., "R0" or 0)
        '''
        if isinstance(reg, str):
            reg = reg.upper()
            if reg not in self.registers.keys():
                raise ValueError(f"Invalid register name {reg}")
            else:
                reg = self.registers[reg]

        return self._get_reg_val(cpu, reg)

    def _get_reg_val(self, cpu, idx):
        '''
        Virtual method. Must be implemented for each architecture to return contents of register specified by idx.
        '''
        raise NotImplementedError()

    def set_reg(self, cpu, reg, val):
        '''
        Set register `reg` to a value where `reg` is either a register name or index (e.g., "R0" or 0)
        '''
        if isinstance(reg, str):
            reg = reg.upper()
            if reg not in self.registers.keys():
                raise ValueError(f"Invalid register name {reg}")
            else:
                reg = self.registers[reg]
        elif not isinstance(reg, int):
            raise ValueError(f"Can't set register {reg}")

        return self._set_reg_val(cpu, reg, val)

    def _set_reg_val(self, cpu, idx, val):
        '''
        Virtual method. Must be implemented for each architecture to return contents of register specified by idx.
        '''
        raise NotImplementedError()

    def get_pc(self, cpu):
        '''
        Returns the current program counter. Must be overloaded if self.reg_pc is None
        '''
        if self.reg_pc:
            return self.get_reg(cpu, self.reg_pc)
        else:
            raise RuntimeError(f"get_pc unsupported for {self.panda.arch_name}")

    def _get_arg_reg(self, idx, convention):
        '''
        return the name of the argument [idx] for the given arch with calling [convention]
        '''

        if self.call_conventions and convention in self.call_conventions:
            if idx < len(self.call_conventions[convention]):
                return self.call_conventions[convention][idx]
            raise NotImplementedError(f"Unsupported argument number {idx}")
        raise NotImplementedError(f"Unsupported convention {convention} for {type(self)}")

    def _get_ret_val_reg(self, cpu, convention):
        if self.reg_retval and convention in self.reg_retval:
            return self.reg_retval[convention]
        raise NotImplementedError(f"Unsupported get_retval for architecture {type(self)} {convention}")


    def set_arg(self, cpu, idx, val, convention='default'):
        '''
        Set arg [idx] to [val] for given calling convention.

        Note for syscalls we define arg[0] as syscall number and then 1-index the actual args
        '''
        reg = self._get_arg_reg(idx, convention)
        return self.set_reg(cpu, reg, val)

    def get_arg(self, cpu, idx, convention='default'):
        '''
        Return arg [idx] for given calling convention. This only works right as the guest
        is calling or has called a function before register values are clobbered.

        Note for syscalls we define arg[0] as syscall number and then 1-index the actual args
        '''
        reg = self._get_arg_reg(idx, convention)
        return self.get_reg(cpu, reg)


    def set_retval(self, cpu, val, convention='default'):
        '''
        Set return val to [val] for given calling convention. This only works
        right after a function call has returned, otherwise the register will contain
        a different value.
        '''
        reg = self._get_ret_val_reg(cpu, convention)
        return self.set_reg(cpu, reg, val)

    def get_retval(self, cpu, convention='default'):
        '''
        Set return val to [val] for given calling convention. This only works
        right after a function call has returned, otherwise the register will contain
        a different value.
        '''
        reg = self._get_ret_val_reg(cpu, convention)
        return self.get_reg(cpu, reg)


    def set_pc(self, cpu, val):
        '''
        Set the program counter. Must be overloaded if self.reg_pc is None
        '''
        if self.reg_pc:
            return self.set_reg(cpu, self.reg_pc, val)
        else:
            raise RuntimeError(f"set_pc unsupported for {self.panda.arch_name}")

    def dump_regs(self, cpu):
        '''
        Print (telescoping) each register and its values
        '''
        for (regname, reg) in self.registers.items():
            val = self.get_reg(cpu, reg)
            print("{}: 0x{:x}".format(regname, val), end="\t")
            telescope(self.panda, cpu, val)

    def dump_stack(self, cpu, words=8):
        '''
        Print (telescoping) most recent `words` words on the stack (from stack pointer to stack pointer + `words`*word_size)
        '''

        base_reg_s = "SP"
        base_reg_val = self.get_reg(cpu, self.reg_sp)
        word_size = int(self.panda.bits/4)

        for word_idx in range(words):
            val_b = self.panda.virtual_memory_read(cpu, base_reg_val+word_idx*word_size, word_size)
            val = int.from_bytes(val_b, byteorder='little')
            print("[{}+0x{:0>2x} == 0x{:0<8x}]: 0x{:0<8x}".format(base_reg_s, word_idx*word_size, base_reg_val+word_idx*word_size, val), end="\t")
            telescope(self.panda, cpu, val)

    def dump_state(self, cpu):
        """
        Print registers and stack
        """
        print("Registers:")
        print(len(self.registers))
        self.dump_regs(cpu)
        print("Stack:")
        self.dump_stack(cpu)

    def get_args(self, cpu, num):
        return [self.get_arg(cpu,i) for i in range(num)]

class ArmArch(PandaArch):
    '''
    Register names and accessors for ARM
    '''
    def __init__(self, panda):
        PandaArch.__init__(self, panda)
        regnames = ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
                    "R8", "R9", "R10", "R11", "R12", "SP", "LR", "IP"]
        self.registers = {regnames[idx]: idx for idx in range(len(regnames)) }
        """Register array for ARM"""

        self.reg_sp      = regnames.index("SP")
        self.reg_pc      = regnames.index("IP")
        self.reg_retaddr = regnames.index("LR")

        self.reg_sp = regnames.index("SP")
        self.reg_retaddr = regnames.index("LR")
        self.call_conventions = {"arm32":         ["R0", "R1", "R2", "R3"],
                                 "syscall": ["R7", "R0", "R1", "R2", "R3"], # EABI
                                 }
        self.call_conventions['default'] = self.call_conventions['arm32']

        self.reg_retval = {"default":    "R0",
                           "syscall":    "R0"}
        self.reg_pc = regnames.index("IP")

    def _get_reg_val(self, cpu, reg):
        '''
        Return an arm register
        '''
        return cpu.env_ptr.regs[reg]

    def _set_reg_val(self, cpu, reg, val):
        '''
        Set an arm register
        '''
        cpu.env_ptr.regs[reg] = val

    def get_return_value(self, env):
        '''
        returns register value used to return results
        '''
        return self.get_reg(env, "R0")

    def get_return_address(self,env):
        '''
        looks up where ret will go
        '''
        return self.get_reg(env, "LR")

class Aarch64Arch(PandaArch):
    '''
    Register names and accessors for ARM64 (Aarch64)
    '''
    def __init__(self, panda):
        PandaArch.__init__(self, panda)

        regnames = ["X0",  "X1",  "X2",  "X3",  "X4",  "X5", "X6", "X7",
                    "XR",  "X9",  "X10", "X11", "X12", "X13", "X14",
                    "X15", "IP0", "IP1", "PR", "X19", "X20", "X21",
                    "X22", "X23", "X24", "X25", "X26", "X27", "X27",
                    "X28", "FP", "LR", "SP"]

        self.reg_sp = regnames.index("SP")

        self.registers = {regnames[idx]: idx for idx in range(len(regnames)) }
        """Register array for ARM"""

        self.reg_sp = regnames.index("SP")
        self.reg_retaddr = regnames.index("LR")

        self.call_conventions = {"arm64":         ["X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7"],
                                 "syscall": ["XR", "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7"]}
        self.call_conventions['default'] = self.call_conventions['arm64']

        self.reg_retval = {"default":    "X0",
                           "syscall":    "X0"}

    def get_pc(self, cpu):
        '''
        Overloaded function to get aarch64 program counter.
        Note the PC is not stored in a general purpose reg
        '''
        return cpu.env_ptr.pc

    def set_pc(self, cpu, val):
        '''
        Overloaded function set AArch64 program counter
        '''
        cpu.env_ptr.pc = val

    def _get_reg_val(self, cpu, reg):
        '''
        Return an aarch64 register
        '''
        return cpu.env_ptr.xregs[reg]

    def _set_reg_val(self, cpu, reg, val):
        '''
        Set an aarch64 register
        '''
        cpu.env_ptr.xregs[reg] = val

    def get_return_value(self, env):
        '''
        returns register value used to return results
        '''
        return self.get_reg(env, "R0")

    def get_return_address(self,env):
        '''
        looks up where ret will go
        '''
        return self.get_reg(env, "LR")

class MipsArch(PandaArch):
    '''
    Register names and accessors for MIPS
    '''

    # Registers are:
    '''
    Register Number	Conventional Name	Usage
    $0	        $zero	Hard-wired to 0
    $1	        $at	Reserved for pseudo-instructions
    $2 - $3	$v0, $v1	Return values from functions
    $4 - $7     $a0 - $a3	Arguments to functions - not preserved by subprograms
    $8 - $15	$t0 - $t7	Temporary data, not preserved by subprograms
    $16 - $23	$s0 - $s7	Saved registers, preserved by subprograms
    $24 - $25	$t8 - $t9	More temporary registers, not preserved by subprograms
    $26 - $27	$k0 - $k1	Reserved for kernel. Do not use.
    $28	        $gp	Global Area Pointer (base of global data segment)
    $29	        $sp	Stack Pointer
    $30	        $fp	Frame Pointer
    $31	        $ra	Return Address
    '''

    def __init__(self, panda):
        super().__init__(panda)
        regnames = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
                    't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
                    's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
                    't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra']

        self.reg_sp = regnames.index('sp')
        self.reg_retaddr = regnames.index("ra")
        self.call_conventions = {"mips":          ["A0", "A1", "A2", "A3"],
                                 "syscall": ["V0", "A0", "A1", "A2", "A3"]}
        self.call_conventions['default'] = self.call_conventions['mips']

        self.reg_retval =  {"default":    "V0",
                            "syscall":    'V0'}


        # note names must be stored uppercase for get/set reg to work case-insensitively
        self.registers = {regnames[idx].upper(): idx for idx in range(len(regnames)) }

    def get_pc(self, cpu):
        '''
        Overloaded function to return the MIPS current program counter
        '''
        return cpu.env_ptr.active_tc.PC

    def set_pc(self, cpu, val):
        '''
        Overloaded function set the MIPS program counter
        '''
        cpu.env_ptr.active_tc.PC = val

    def _get_reg_val(self, cpu, reg):
        '''
        Return a mips register
        '''
        return cpu.env_ptr.active_tc.gpr[reg]

    def _set_reg_val(self, cpu, reg, val):
        '''
        Set a mips register
        '''
        cpu.env_ptr.active_tc.gpr[reg] = val

    def get_return_value(self, env):
        '''
        returns register value used to return results
        '''
        return self.get_reg(env, "V0")

    def get_call_return(self,env):
        '''
        looks up where ret will go
        '''
        return self.get_reg(env, "RA")

class X86Arch(PandaArch):
    '''
    Register names and accessors for x86
    '''

    def __init__(self, panda):
        super().__init__(panda)
        regnames = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI']
        # XXX Note order is A C D B, because that's how qemu does it . See target/i386/cpu.h

        # Note we don't set self.call_conventions because stack-based arg get/set is
        # not yet supported
        self.reg_retval = {"default":    "EAX",
                           "syscall":    "EAX"}

        self.reg_sp = regnames.index('ESP')
        self.registers = {regnames[idx]: idx for idx in range(len(regnames)) }

    def get_pc(self, cpu):
        '''
        Overloaded function to return the x86 current program counter
        '''
        return cpu.env_ptr.eip

    def set_pc(self, cpu, val):
        '''
        Overloaded function to set the x86 program counter
        '''
        cpu.env_ptr.eip = val

    def _get_reg_val(self, cpu, reg):
        '''
        Return an x86 register
        '''
        return cpu.env_ptr.regs[reg]

    def _set_reg_val(self, cpu, reg, val):
        '''
        Set an x86 register
        '''
        cpu.env_ptr.regs[reg] = val

    def get_return_value(self, env):
        '''
        returns register value used to return results
        '''
        return self.get_reg(env, "EAX")

    def get_return_address(self,env):
        '''
        looks up where ret will go
        '''
        esp = self.get_reg(env,"ESP")
        return self.panda.virtual_memory_read(env,esp,4,fmt='int')

class X86_64Arch(PandaArch):
    '''
    Register names and accessors for x86_64
    '''

    def __init__(self, panda):
        super().__init__(panda)
        # The only place I could find the R_ names is in tcg/i386/tcg-target.h:50
        regnames = ['RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI',
                    'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15']
        # XXX Note order is A C D B, because that's how qemu does it

        self.call_conventions = {'sysv':           ['RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9'],
                                 'syscall': ['RAX', 'RDI', 'RSI', 'RDX', 'R10', 'R8', 'R9']}

        self.call_conventions['default'] = self.call_conventions['sysv']

        self.reg_sp = regnames.index('RSP')
        self.reg_retval = {'sysv': 'RAX',
                           'syscall': 'RAX'}
        self.reg_retval['default'] = self.reg_retval['sysv']

        self.registers = {regnames[idx]: idx for idx in range(len(regnames)) }

    def get_pc(self, cpu):
        '''
        Overloaded function to return the x86_64 current program counter
        '''
        return cpu.env_ptr.eip

    def set_pc(self, cpu, val):
        '''
        Overloaded function to set the x86_64 program counter
        '''
        cpu.env_ptr.eip = val

    def _get_reg_val(self, cpu, reg):
        '''
        Return an x86_64 register
        '''
        return cpu.env_ptr.regs[reg]

    def _set_reg_val(self, cpu, reg, val):
        '''
        Set an x86_64 register
        '''
        cpu.env_ptr.regs[reg] = val

    def get_return_value(self, env):
        '''
        returns register value used to return results
        '''
        return self.get_reg(env, "RAX")

    def get_return_address(self,env):
        '''
        looks up where ret will go
        '''
        esp = self.get_reg(env,"RSP")
        return self.panda.virtual_memory_read(env,esp,8,fmt='int')
