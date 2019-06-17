# Module to manage "user" interactions with guest via serial

import socket
import threading
import queue
import time
import os
from enum import Enum
from collections import namedtuple
from tempfile import NamedTemporaryFile
from panda_expect import Expect

class CmdType(Enum):
    MONITOR = 0,
    SERIAL = 1,
#    PYTHON = 2,

cmd = namedtuple('Command', 'id type command')


class UserThread:
    def __init__(self, libpanda, ffi, expect_prompt):
        self.console = None
        self.thread = None
        self.running = True

        # Queue for commands to be populated in main thread, consumed in worker
        self.q = queue.Queue()

        # List of finished commands tuples of (id, result) to be populated by worker, consumed in main
        self.finished = queue.Queue()

        self.serial_file = "/tmp/pypanda" #NamedTemporaryFile(prefix="pypanda_").name
        self.serial_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.libpanda = libpanda
        self.ffi = ffi
        self.expect_prompt = expect_prompt
        self.cmd_idx = 0


        # Start run_loop in a thread
        self.thread = threading.Thread(target=self.run_loop)
        self.thread.start()

    def get_panda_serial_arg(self):
        # Return panda argument to connect to serial file
        return ['-serial', 'unix:{},server,nowait'.format(self.serial_file)]

    def queue_monitor_cmd(self, command):
        self.q.put(cmd(self.cmd_idx, CmdType.MONITOR, command))
        self.cmd_idx += 1

    def queue_serial_cmd(self, command):
        self.q.put(cmd(self.cmd_idx, CmdType.SERIAL, command))
        self.cmd_idx += 1

    #def queue_python_cmd(self, command, args=[]):
    #    self.q.put(cmd(CmdType.PYTHON, "{}({})".format(command, ", ".join(args))))

    def get_completed(self):
        # Pop an item off the finished list
        try:
            r = self.finished.get_nowait()
        except queue.Empty:
            return (None, None)

        self.finished.task_done()
        return r


    def stop(self):
        self.running  = False
        if self.console:
            self.console.abort()
        self.thread.join()

    def run_loop(self):
        while self.running:
            try: # Only wait a few seconds so if runnuing becomes false we can exit
                item = self.q.get(timeout=5) # Wait for an item to become available
            except queue.Empty:
                continue

            if item is None: # Empty queue
                continue

            # Connect to serial socket and setup console if necessary
            if not self.console:
                self.serial_socket.connect(self.serial_file)
                self.console = Expect(self.serial_socket, quiet=True)

            (cid, proto, cmd) = item

            # Run command via specified channel, WAIT for result (blocking)
            print("Run command {} via {}".format(cmd, proto))
            if proto == CmdType.MONITOR:
                result = self.send_monitor_sync(cmd)
            elif proto == CmdType.SERIAL:
                result = self.send_serial_sync(cmd)
            else:
                raise RuntimeError("Unsupported protocol {}".format(proto))

            if not self.running:
                self.q.task_done()
                return

            print("Finished: {}".format(result if result else "(no output)"))

            self.q.task_done()
            self.finished.put((cid, result))

    def send_serial_sync(self, cmd):
        assert(self.expect_prompt), "Expect prompt required for serial commands"
        self.console.sendline(cmd.encode("utf8"))
        result = self.console.expect(self.expect_prompt, last_cmd=cmd)
        return result

    def send_monitor_sync(self, cmd):
        buf = self.ffi.new("char[]", bytes(cmd,"UTF-8"))
        result = self.libpanda.panda_monitor_run(buf)
        if result != self.ffi.NULL:
            return self.ffi.string(result)
        return None
