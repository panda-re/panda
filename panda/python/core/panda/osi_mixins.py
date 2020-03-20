from .utils import progress
from .ffi_importer import ffi

class osi_mixins():
    def load_osi(self):
        progress("load_osi")
        self.load_plugin("osi")
        if "linux" in self.os:
            self.load_plugin("osi_linux")
        else:
            print("Not supported yet for os: %s" % self.os)

    def require_osi(self):
        if not 'osi' in self.plugins:
            self.load_osi()

    def get_current_process(self, cpustate):
        self.require_osi()
        process = self.plugins['osi'].get_current_process(cpustate)
        return process

    def get_processes(self, cpustate):
        self.require_osi()
        return self.plugins['osi'].get_processes(cpustate)

    def get_libraries(self, cpustate, current):
        self.require_osi()
        return self.plugins['osi'].get_libraries(cpustate,current)

    def get_modules(self, cpustate):
        self.require_osi()
        return self.plugins['osi'].get_modules(cpustate)

    def get_current_thread(self, cpustate):
        self.load_osi()
        self.require_osi()
        return self.plugins['osi'].get_current_thread(cpustate)

    def get_process_name(self, cpu):
        current = self.get_current_process(cpu)
        if current == ffi.NULL or current.name == ffi.NULL:
            return 0
        current_name = ffi.string(current.name).decode('utf8', 'ignore')
        return current_name

