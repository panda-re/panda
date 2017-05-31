import os
import select
import sys

from datetime import datetime
from errno import EAGAIN, EWOULDBLOCK

class TimeoutExpired(Exception): pass

class Expect(object):
    def __init__(self, filelike, logfile=None, quiet=False):
        if type(filelike) == int:
            self.fd = filelike
        else:
            self.fd = filelike.fileno()
        self.poller = select.poll()
        self.poller.register(self.fd, select.POLLIN)

        if logfile is None: logfile = os.devnull
        self.logfile = open(logfile, "wb")
        self.quiet = quiet

    def __del__(self):
        self.logfile.close()

    def expect(self, expectation, timeout=30):
        sofar = bytearray()
        start_time = datetime.now()
        time_passed = 0
        while timeout is None or time_passed < timeout:
            if timeout is not None:
                time_passed = (datetime.now() - start_time).total_seconds()
                time_left = timeout - time_passed
            else:
                time_left = float("inf")
            ready = self.poller.poll(min(time_left, 1))

            if self.fd in [fd for (fd, _) in ready]:
                try:
                    char = os.read(self.fd, 1)
                except OSError as e:
                    self.sofar = str(sofar)
                    if e.errno in [EAGAIN, EWOULDBLOCK]:
                        continue
                    else: raise
                self.logfile.write(char)
                if not self.quiet: sys.stdout.write(char)

                sofar.extend(char)
                if sofar.endswith(expectation.encode('utf8')):
                    self.logfile.flush()
                    if not self.quiet: sys.stdout.flush()
                    sofar.extend(b'\n')
                    return sofar.decode('utf8')
        self.logfile.flush()
        if not self.quiet: sys.stdout.flush()
        self.sofar = sofar.decode('utf8')
        raise TimeoutExpired()

    def send(self, msg):
        os.write(self.fd, msg)
        self.logfile.write(msg)
        self.logfile.flush()

    def sendline(self, msg=""):
        self.send(msg + b"\n")

