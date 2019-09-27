from .utils import progress
from .autogen.panda_datatypes import ffi

class osi_mixins():
    def load_osi(self):
        progress("load_osi")
        self.load_plugin("osi")
        if "linux" in self.os:
            self.load_plugin("osi_linux")
        else:
            print("Not supported yet for os: %s" % self.os)

    def get_current_process(self, cpustate):
        if not hasattr(self, "libpanda_osi"):
            self.load_osi() 
        process = self.libpanda_osi.get_current_process(cpustate)
        return process

    def get_processes(self, cpustate):
        if not hasattr(self, "libpanda_osi"):
            self.load_osi() 
        return self.libpanda_osi.get_processes(cpustate)

    def get_libraries(self, cpustate, current):
        if not hasattr(self, "libpanda_osi"):
            self.load_osi() 
        return self.libpanda_osi.get_libraries(cpustate,current)

    def get_modules(self, cpustate):
        if not hasattr(self, "libpanda_osi"):
            self.load_osi() 
        return self.libpanda_osi.get_modules(cpustate)

    def get_current_thread(self, cpustate):
        if not hasattr(self, "libpanda_osi"):
            self.load_osi() 
        return self.libpanda_osi.get_current_thread(cpustate)

    def get_process_name(self, cpu):
        current = self.get_current_process(cpu)
        if current == ffi.NULL or current.name == ffi.NULL:
            return 0
        current_name = ffi.string(current.name).decode('utf8', 'ignore')
        return current_name

