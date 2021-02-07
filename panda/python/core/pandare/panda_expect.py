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
        if isinstance(expectation, bytes):
            expectation = expectation.decode()
        self.expectation_re = re.compile(expectation)
        self.expectation_ends_re = re.compile(r'.*' + expectation)

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

    def unansi(self, msg):
        '''
        Given a string with ansi control codes, emulate behavior to generate the resulting string. 
        Poorly tested.

        Split input into a list of ('fn', [args]) / ('text', ['foo']) ansi commands then render real text output

        See https://notes.burke.libbey.me/ansi-escape-codes/ and
        http://ascii-table.com/ansi-escape-sequences-vt-100.php for ansi escape code details
        '''

        if b'\x1b' not in msg:
            text = "".join([chr(x) for x in msg])
            return text

        start_args = re.compile(br"^(\d+);")
        last_arg = re.compile(rb"^(\d+)")

        last_text = ""
        reformatted = []
        idx = 0 # XXX: mutates during loop
        while idx < len(msg):
            if msg[idx] != 0x1b:
                last_text += chr(msg[idx])
            else:
                if len(last_text):
                    reformatted.append(('text', [last_text]))
                    last_text = ""

                if idx+3 <= len(msg) and msg[idx+1] == ord('['):
                    args = []
                    shift = idx+2
                    arg_s = msg[shift:]
                    while start_args.match(arg_s):
                        arg = start_args.match(arg_s).groups()[0].decode()
                        args.append(arg)
                        shift += len(arg)+1 # for ;
                        arg_s = msg[shift:]

                    # Last arg is just #
                    if last_arg.match(arg_s):
                        arg = last_arg.match(arg_s).groups()[0].decode()
                        shift += len(arg)
                        args.append(arg)
                        arg_s = msg[shift:]

                    # Next is one char for cmd
                    cmd = chr(msg[shift])
                    reformatted.append((cmd, args))

                    idx = shift # final char
            idx += 1
        if len(last_text):
            reformatted.append(('text', [last_text]))

        # Now render it!
        lines_out = [" "*100]
        cur_line = 0
        line_pos = 0
        store_ptr = (0, 0)

        for (typ, args) in reformatted:
            if typ == 'text':
                n = args[0]
                #print(n, line_pos)
                for idx, char in enumerate(n):
                    if char == '\n':
                        cur_line += 1 
                        while cur_line >= len(lines_out):
                            lines_out.append(" "*100)
                    if char == '\r':
                        line_pos = 0

                    line = list(lines_out[cur_line])
                    if (line_pos) >= len(line):
                        line.append(char)
                    else:
                        line[line_pos] = char
                    lines_out[cur_line] = "".join(line)

                    if char not in ['\n', '\r']:
                        line_pos += 1

            else:
                args[:] = [int(x) for x in args]
                #print(typ, args)

                if typ == 'A':
                    n = args[0]

                    if cur_line - n < 0: # Need to shift
                        cur_line = 0
                    else:
                        cur_line -= n
                    assert(cur_line >= 0)

                elif typ == 'B':
                    n = args[0]
                    cur_line += n
                    while cur_line >= len(lines_out):
                        lines_out.append(" "*100)

                elif typ == 'D':
                    n = 1 # Default move left 1
                    if len(args):
                        n = args[0]

                    line_pos -= n
                    if line_pos < 0:
                        line_pos = 0
                    assert(line_pos >= 0)

                elif typ == 'J':
                    # Optional arg 0, 1, 2
                    n = 0 # default
                    if len(args):
                        n = args[0]
                    if n == 0:
                        # clear down
                        lines_out = lines_out[:cur_line+1]
                    elif n == 1:
                        # clear up
                        lines_out = lines_out[cur_line:]
                    elif n == 2:
                        # clear everything
                        lines_out = [""]
                        cur_line = 0
                        line_pos = 0
                        store_ptr = (0, 0)

                elif typ == 'K':
                    # Optional arg 0, 1, 2
                    n = 0 # default
                    if len(args):
                        n = args[0]
                    if n == 0:
                        # clear right of cursor
                        lines_out[cur_line] = lines_out[cur_line][:line_pos]
                    elif n == 1:
                        # clear left of cursor
                        lines_out[cur_line] = (" "*line_pos)+lines_out[cur_line][line_pos:]
                    elif n == 2:
                        # clear whole line
                        lines_out[cur_line] = " "*len(lines_out[cur_line])

                elif typ == 'H':
                    n = args[0]-1
                    m = args[1]-1
                    cur_line = n
                    line_pos = m

                    while cur_line >= len(lines_out):
                        lines_out.append("")

                    while line_pos > len(lines_out[cur_line]):
                        lines_out[cur_line] += " "

                elif typ == 'T':
                    # Scroll window down
                    pass
                elif typ == 'S':
                    # Scroll window up
                    pass

                elif typ == 's':
                    store_ptr = (cur_line, line_pos)
                elif typ == 'u':
                    (cur_line, line_pos) = store_ptr

                else:
                    raise ValueError(f"Unsupporte ANSI command {typ}")
            #tmp = "\n".join(lines_out)
            #print(f"Coords ({cur_line}, {line_pos}): {tmp}\n--")
        return "\n".join(lines_out)

    def expect(self, expectation=None, timeout=30):
        '''
        Assumptions: as you send a command, the guest may send back
            The same command + ansi control codes.
            The epxectation value will show up on the start of a line.
            The command you send should not be returned
        '''

        if expectation:
            raise ValueError("Deprecated interface - must set expectation in class init")

        if self.fd is None:
            raise RuntimeError("Must connect() prior to expect()")

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

                plaintext = self.unansi(sofar)

                # Done parsing - make meaning from the buffer
                # We may have our command echoed back + control characters before the result
                if self.expectation_ends_re.match(("\n"+plaintext).split("\n")[-1]) != None:
                    #print("\nFinal line matches -- raw message '{}'".format(repr(plaintext)))

                    # Strip each line
                    resp = [x.strip() for x in plaintext.replace("\r", "").split("\n")]

                    # Check if last line matches prompt (again?) - if so drop it from result
                    last_line = resp[-1]
                    if self.expectation_re.match(last_line):
                        resp[:] = resp[:-1] # drop next prompt
                        plaintext= "\n".join(resp)

                    self.logfile.flush()
                    if not self.quiet: sys.stdout.flush()

                    return plaintext

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

        self.last_msg = msg.decode()
        os.write(self.fd, msg)
        self.logfile.write(msg)
        self.logfile.flush()

    def send_eol(self): # Just send an EOL
        if self.last_msg:
            self.last_msg+="\n"
        os.write(self.fd, b"\n")
        self.logfile.write(b"\n")
        self.logfile.flush()


    def sendline(self, msg=b""):
        assert(self.fd is not None), "Must connect before sending"
        self.send(msg + b"\n")

