"""
Convenience functions to interact with the Operating System Instrospection (OSI) class of plugins.
"""

from .utils import progress
from .ffi_importer import ffi

class GArrayIterator():
    '''
    Iterator which will run a function on each iteration incrementing
    the second argument. Useful for GArrays with an accessor function
    that takes arguments of the GArray and list index. e.g., osi's
    get_one_module.
    '''
    def __init__(self, func, garray, garray_len, cleanup_fn):
        self.garray = garray
        self.garray_len = garray_len
        self.current_idx = 0
        self.func = func
        self.cleanup_func = cleanup_fn

    def __iter__(self):
        self.current_idx = 0
        return self

    def __next__(self):
        if self.current_idx >= self.garray_len:
            raise StopIteration
        # Would need to make this configurable before using MappingIter with other types
        ret = self.func(self.garray, self.current_idx)
        self.current_idx += 1
        return ret

    def __del__(self):
        self.cleanup_func(self.garray)

class osi_mixins():
    def set_os_name(self, os_name):
        """
        Set OS target. Equivalent to "-os" flag on the command line. Matches the form of:
        
            "windows[-_]32[-_]xpsp[23]",
            "windows[-_]32[-_]7",
            "windows[-_]32[-_]2000",
            "linux[-_]32[-_].+",
            "linux[-_]64[-_].+",

            Parameters:
                os_name: string matching the format for the os flag.
            
            Returns:
                None
        """
        os_name_new = ffi.new("char[]", bytes(os_name, "utf-8"))
        self.libpanda.panda_set_os_name(os_name_new)


    def get_mappings(self, cpu):
        '''
        Get all active memory mappings in the system.

            Requires: OSI

            Parameters:
                cpu: CPUState struct

            Returns:
                Iterator of `OsiModule` structures
        '''
        current = self.plugins['osi'].get_current_process(cpu)
        maps = self.plugins['osi'].get_mappings(cpu, current)
        map_len = self.garray_len(maps)
        return GArrayIterator(self.plugins['osi'].get_one_module, maps, map_len, self.plugins['osi'].cleanup_garray)

    def get_processes(self, cpu):
        '''
        Get all running processes in the system. Includes kernel modules on Linux.

            Requires: OSI

            Parameters:
                cpu: CPUState struct

            Returns:
                Iterator of `OsiProc` structures
        '''
        processes = self.plugins['osi'].get_processes(cpu)
        processes_len = self.garray_len(processes)
        return GArrayIterator(self.plugins['osi'].get_one_proc, processes, processes_len, self.plugins['osi'].cleanup_garray)

    def get_processes_dict(self, cpu):
        '''
        Get all running processes for the system at this moment in time as a dictionary.

        The dictionary maps proceses by their PID. Each mapping returns a dictionary containing the process name, its pid,
        and its parent pid (ppid).

            Requires: OSI

            Parameters:
                cpu: CPUState struct

            Returns:
                Dictionary as described above.
        '''

        procs = {} #pid: {name: X, pid: Y, parent_pid: Z})

        for proc in self.get_processes(cpu):
            assert(proc != ffi.NULL)
            assert(proc.pid not in procs)
            procs[proc.pid] = {"name": ffi.string(proc.name).decode('utf8', 'ignore'), 'pid': proc.pid, 'parent_pid': proc.ppid}
            assert(not (proc.pid != 0 and proc.pid == proc.ppid)) # No cycles allowed other than at 0
        return procs
