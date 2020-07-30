"""
Provides the ability to interact with a QEMU attached gdb session by setting and clearing breakpoints. Experimental.
"""


from .ffi_importer import ffi

class gdb_mixins():
    def set_breakpoint(self, cpu, pc):
        '''
        Set a GDB breakpoint such that when the guest hits PC, execution is paused and an attached
        GDB instance can introspect on guest memory. Requires starting panda with -s, at least for now
        '''
        BP_GDB = 0x10
        self.libpanda.cpu_breakpoint_insert(cpu, pc, BP_GDB, ffi.NULL)

    def clear_breakpoint(self, cpu, pc):
        '''
        Remove a breakpoint
        '''
        BP_GDB = 0x10
        self.libpanda.cpu_breakpoint_remove(cpu, pc, BP_GDB)
