# Custom library for interacting/expecting data via serial-like FDs

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
        self.sofar = ''
        self.last_msg = None
        self.bytessofar = bytearray()
        self.running = True

    def __del__(self):
        self.logfile.close()

    def abort(self):
        self.running = False

    def expect(self, expectation, last_cmd=b'', timeout=30):
        # Wait until we get expectation back, up to timeout. Return data between last_command and expectation
        sofar = bytearray()
        start_time = datetime.now()
        time_passed = 0
        while (timeout is None or time_passed < timeout) and self.running:
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
                if not self.quiet: sys.stdout.write(char.decode("utf-8","ignore"))

                sofar.extend(char)
                if sofar.endswith(expectation.encode('utf8')):
                    #print("Raw message '{}'".format(sofar))

                    if b"\r\n" in sofar: # Serial will echo our command back, try to strip it out
                        resp = sofar.split(b"\r\n")
                        if resp[0].decode('utf8').replace(" \r", "") == last_cmd:
                            resp[:] = resp[1:] # drop last cmd

                        if resp[-1].decode('utf8') == expectation:
                            resp[:] = resp[:-1] # drop next prompt

                        sofar= b"\r\n".join(resp)
                    sofar = sofar.strip()
                    self.logfile.flush()
                    if not self.quiet: sys.stdout.flush()
                    return sofar.decode('utf8')

        if not self.running: # Aborted
            return None

        self.logfile.flush()
        if not self.quiet: sys.stdout.flush()
        self.sofar = sofar.decode('utf8')
        raise TimeoutExpired()

    def send(self, msg):
        self.last_msg = msg
        os.write(self.fd, msg)
        self.logfile.write(msg)
        self.logfile.flush()

    def send_eol(self):
        if self.last_msg:
            self.last_msg+=b"\n"
        os.write(self.fd, b"\n")
        self.logfile.write(b"\n")
        self.logfile.flush()


    def sendline(self, msg=b""):
        self.send(msg + b"\n")
        self.last_msg = msg+b"\n"

