import shutil
from pathlib import Path
from panda import ffi

class ProcWriteCapture():

    '''
    For a named process, capture stdout/stderr and any file writes from the hypervisor, mirror results to log directory.
    Requires Linux OSI.
    '''

    def __init__(self, panda, proc_name, log_dir = None, rm_existing_logs = False):

        self._panda = panda
        self._files_written = set()
        self._proc_name = proc_name
        self._rm = rm_existing_logs

        if log_dir == None:
            self._log_dir = Path(__file__).parent.absolute().joinpath(self._proc_name)
        else:
            self._log_dir = Path(log_dir).joinpath(self._proc_name)

        # Setup logging dir
        self._log_dir.mkdir(parents=True, exist_ok=True)
        if self._rm:
            shutil.rmtree(self._log_dir)

        # Mirror writes
        @self._panda.ppp("syscalls2", "on_sys_write_enter")
        def proc_write_capture_on_sys_write_enter(cpu, pc, fd, buf, cnt):

            curr_proc = panda.plugins['osi'].get_current_process(cpu)
            curr_proc_name = ffi.string(curr_proc.name).decode()
            if self._proc_name == curr_proc_name:

                try:
                    data = panda.virtual_memory_read(cpu, buf, cnt)
                except ValueError:
                    raise RuntimeError("Failed to read buffer: proc \'{}\', addr 0x{:016x}".format(curr_proc_name, buf))

                file_name_ptr = panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, curr_proc, fd)
                file_path = ffi.string(file_name_ptr).decode()

                # For informational purposes only, collection not reliant on this exact mapping
                if fd == 1: # POSIX stdout
                    file_path += ".stdout"
                elif fd == 2: # POSIX stderr
                    file_path += ".stderr"

                log_file = self._log_dir.joinpath(file_path.replace("//", "_").replace("/", "_"))
                with open(log_file, "ab") as f:
                    f.write(data)

                self._files_written.add(str(log_file))

    def printed_err(self):
        return (self._stderr_log_file in self._files_written)

    def get_files_written(self):
        return self._files_written
