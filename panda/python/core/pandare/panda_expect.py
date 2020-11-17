""" Custom library for interacting/expecting data via serial-like FDs"""

import os
import re
import select
import sys
import string

from datetime import datetime
from errno import EAGAIN, EWOULDBLOCK
from colorama import Fore, Style

class TimeoutExpired(Exception): pass

class Expect(object):
    def __init__(self, filelike=None, expectation=None, logfile=None, quiet=False, consume_first=False):
        if filelike is None: # Must later use connect(filelike)
            self.fd = None
        else:
            self.connect(filelike)

        if logfile is None: logfile = os.devnull
        self.logfile = open(logfile, "wb")
        self.quiet = quiet
        self.sofar = ''
        self.last_msg = None
        self.bytessofar = bytearray()
        self.running = True
        self.update_expectation(expectation)

        # If consumed_first is false, we'll consume a message before anything else. Requires self.expectation to be set
        self.consumed_first = True
        if consume_first:
            self.consumed_first = False

    def update_expectation(self, expectation):
        self.expectation_re = re.compile(expectation)
        self.expectation_ends_re = re.compile(rb'.*' + expectation)

    def connect(self, filelike):
        if type(filelike) == int:
            self.fd = filelike
        else:
            self.fd = filelike.fileno()
        self.poller = select.poll()
        self.poller.register(self.fd, select.POLLIN)

    def is_connected(self):
        return self.fd != None

    def __del__(self):
        self.logfile.close()

    def abort(self):
        self.running = False

    def expect(self, expectation=None, timeout=30):
        '''
        Assumptions: as you send a command, the guest may send back
            The same command + ansi control codes.
            The epxectation value will show up on the start of a line.
            The command you send should not be returned
        '''

        if expectation:
            raise ValueError("Deprecated interface - must set expectation in class init")

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

                # Done parsing - make meaning from the buffer
                # We may have our command echoed back + control characters before the result
                if self.expectation_ends_re.match((b"\n"+sofar).split(b"\n")[-1]) != None:
                    #print("\nFinal line matches -- raw message '{}'".format(sofar))

                    if b"\x1b" in sofar:
                        # We have control chracters - assume it's a normal linux guest
                        # Approach here is to drop the messages before and including ctrl chars
                        results = []
                        past_ansi = False
                        for line in sofar.split(b"\r"):
                            if b"\x1b" in line:
                                past_ansi = True
                                continue

                            elif past_ansi:
                                results.append(line)
                        sofar = b"\r".join(results)

                    # Try joining all lines together and searching for lastmsg
                    joined = b"".join([x.strip() for x in sofar.split(b"\r")])
                    if self.last_msg and joined.startswith(self.last_msg.strip()):
                        results = []
                        # Go through lines until we find one that ends with last_msg
                        past_echo = False
                        current = b""
                        end_of_echo = 0
                        for idx, line in enumerate(sofar.split(b"\r")):
                            if self.last_msg.strip().endswith(current+line.strip()):
                                current += line.strip()
                                end_of_echo = idx

                        for idx, line in enumerate(sofar.split(b"\r")):
                            if idx > end_of_echo:
                                results.append(line)

                        sofar = b"\r".join(results)



                    if b"\r\n" in sofar: # Drop next prompt
                        resp = sofar.split(b"\r\n")

                        last_line = resp[-1]
                        if self.expectation_re.match(last_line) != None:
                            resp[:] = resp[:-1] # drop next prompt
                            sofar= b"\r\n".join(resp)

                    sofar = sofar.strip()
                    self.logfile.flush()
                    if not self.quiet: sys.stdout.flush()

                    return sofar.decode('utf8', 'ignore')

        if not self.running: # Aborted
            return None

        self.logfile.flush()
        if not self.quiet: sys.stdout.flush()

        self.sofar = sofar.decode('utf8')
        raise TimeoutExpired("Read message \n{}\n".format(self.sofar))

    def send(self, msg):
        if not self.consumed_first: # Before we send anything, consume header
            pre = self.expect("")
            self.consumed_first = True

        self.last_msg = msg
        os.write(self.fd, msg)
        self.logfile.write(msg)
        self.logfile.flush()

    def send_eol(self): # Just send an EOL
        if self.last_msg:
            self.last_msg+=b"\n"
        os.write(self.fd, b"\n")
        self.logfile.write(b"\n")
        self.logfile.flush()


    def sendline(self, msg=b""):
        self.send(msg + b"\n")

