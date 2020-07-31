'''
Methods that directly pass data to/from PANDA with no extra logic beyond argument reformatting.
'''

from .ffi_importer import ffi

class libpanda_mixins():
    def set_pandalog(self, name):
        '''
        Start up pandalog with specified file

            Parameters:
                name: file to output data to
            
            Returns:
                None
        '''
        charptr = ffi.new("char[]", bytes(name, "utf-8"))
        self.libpanda.panda_start_pandalog(charptr)

    def enable_memcb(self):
        '''
        Enable memory callbacks. Must be called for memory callbacks to work.
        pypanda enables this automatically with some callbacks.
        '''
        self._memcb = True
        self.libpanda.panda_enable_memcb()
    
    def disable_memcb(self):
        '''
        Disable memory callbacks. Must be enabled for memory callbacks to work.
        pypanda enables this automatically with some callbacks.
        '''
        self._memcb = False
        self.libpanda.panda_disable_memcb()

    def virt_to_phys(self, env, addr):
        '''
        Convert virtual address to physical address.

            Parameters:
                env: CPUState struct
                addr (int): virtual address to convert
            
            Return:
                physical address as python int
        '''
        return self.libpanda.panda_virt_to_phys_external(env, addr)

    def enable_plugin(self, handle):
        '''
        Enable plugin.

            Parameters:
                handle: pointer to handle returned by plugin
            
            Return:
                None
        '''
        self.libpanda.panda_enable_plugin(handle)

    def disable_plugin(self, handle):
        '''
        Disable plugin.

            Parameters:
                handle: pointer to handle returned by plugin
            
            Return:
                None
        '''
        self.libpanda.panda_disable_plugin(handle)

    def enable_llvm(self):
        '''
        Enables the use of the LLVM JIT in replacement of the TCG (QEMU intermediate language and compiler) backend. 
        '''
        self.libpanda.panda_enable_llvm()

    def disable_llvm(self):
        '''
        Disables the use of the LLVM JIT in replacement of the TCG (QEMU intermediate language and compiler) backend. 
        '''
        self.libpanda.panda_disable_llvm()

    def enable_llvm_helpers(self):
        '''
        Enables the use of Helpers for the LLVM JIT in replacement of the TCG (QEMU intermediate language and compiler) backend. 
        '''
        self.libpanda.panda_enable_llvm_helpers()

    def disable_llvm_helpers(self):
        '''
        Disables the use of Helpers for the LLVM JIT in replacement of the TCG (QEMU intermediate language and compiler) backend. 
        '''
        self.libpanda.panda_disable_llvm_helpers()

    def flush_tb(self):
        '''
        This function requests that the translation block cache be flushed as soon as possible. If running with translation block chaining turned off (e.g. when in LLVM mode or replay mode), this will happen when the current translation block is done executing.
        Flushing the translation block cache is additionally necessary if the plugin makes changes to the way code is translated. For example, by using panda_enable_precise_pc.
        '''
        return self.libpanda.panda_flush_tb()

    def enable_precise_pc(self):
        '''
        By default, QEMU does not update the program counter after every instruction.
        This function enables precise tracking of the program counter. After enabling precise PC tracking, the program counter will be available in env->panda_guest_pc and can be assumed to accurately reflect the guest state.
        '''
        self.libpanda.panda_enable_precise_pc()

    def disable_precise_pc(self):
        '''
        By default, QEMU does not update the program counter after every instruction.
        This function disables precise tracking of the program counter.
        '''
        self.libpanda.panda_disable_precise_pc()

    def in_kernel(self, cpustate):
        '''
        Returns true if the processor is in the privilege level corresponding to executing kernel code for any of the PANDA supported architectures.
        '''
        return self.libpanda.panda_in_kernel_external(cpustate)

    def g_malloc0(self, size):
        '''
        Helper function to call glib malloc

            Parameters:
                size: size to call with malloc
            
            Returns:
                buffer of that size from malloc
        '''
        return self.libpanda.g_malloc0(size)

    def current_sp(self, cpustate):
        '''
        Get current stack pointer

            Parameters:
                cpustate: CPUState struct

            Return:
                integer value of stack pointer
        '''
        return self.libpanda.panda_current_sp_external(cpustate)

    def current_pc(self, cpustate):
        '''
        Get current program counter

            Parameters:
                cpustate: CPUState struct

            Return:
                integer value of current program counter
        '''
        return self.libpanda.panda_current_pc(cpustate)

    def current_asid(self, cpustate):
        '''
        Get current Application Specific ID
            
            Parameters:
                cpustate: CPUState struct

            Return:
                integer value of current ASID
        '''
        return self.libpanda.panda_current_asid(cpustate)

    def disas2(self, code, size):
        '''
        Call panda_disas to diasassemble an amount of code at a pointer.
        FIXME: seem to not match up to PANDA definition
        '''
        self.libpanda.panda_disas(code, size)

    def cleanup(self):
        '''
        Unload all plugins and close pandalog.
        '''
        self.libpanda.panda_cleanup()

    def was_aborted(self):
        '''
        Returns true if panda was aborted.
        '''
        return self.libpanda.panda_was_aborted()

    def get_cpu(self):
        '''
        This function returns first_cpu CPUState object from QEMU.
        XXX: You rarely want this
        '''
        return self.libpanda.get_cpu()

    def garray_len(self, garray):
        '''
        Convenience function to get array length of glibc array.
        '''
        return self.libpanda.garray_len(garray)

    def panda_finish(self):
        '''
        Final stage call to underlying panda_finish with initialization.
        '''
        return self.libpanda.panda_finish()

    def rr_get_guest_instr_count(self):
        '''
        Returns record/replay guest instruction count.
        '''
        return self.libpanda.rr_get_guest_instr_count_external()
