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
    def __init__(self, name, filelike=None, expectation=None, logfile=None, quiet=False, consume_first=False):

        self.name = name

        if logfile is None: logfile = os.devnull
        self.logfile = open(logfile, "wb")

        if filelike is None: # Must later use connect(filelike)
            self.fd = None
        else:
            self.connect(filelike)

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
        self.last_prompt = expectation # approximation
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

        First we split input into a list of ('fn', [args]) / ('text', ['foo']) ansi commands then
        evaluate the commands to render real text output

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
                    while start_args.match(arg_s) and shift < len(msg):
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
                    if shift < len(msg):
                        cmd = chr(msg[shift])
                        reformatted.append((cmd, args))
                    

                    idx = shift # final char
            idx += 1
        if len(last_text):
            reformatted.append(('text', [last_text]))

        # Now render it!
        # Note the very first line will \r to beginning, then 'C' forward to go past expect prompt

        lines_out = [" "*len(self.last_prompt)] # Starting point - it's an approximation since we don't know real current prompt
        cur_line = 0
        line_pos = len(self.last_prompt)
        store_ptr = (0, 0)

        def _dump(lines_out, cur_line, line_pos):
            print("-"*100)
            for idx, line in enumerate(lines_out):
                print("'", line, "'")
                if cur_line == idx:
                    print((" "*(line_pos-1) if line_pos > 0 else "") + "^")
            print("="*100)

        for idx, (typ, args) in enumerate(reformatted):
            #print(typ, args)
            if typ == 'text':
                n = args[0]
                for idx, char in enumerate(n):
                    if char == '\n':
                        cur_line += 1 
                        while cur_line >= len(lines_out):
                            lines_out.append("")
                    if char == '\r':
                        line_pos = 0
                        continue # Don't clobber old char

                    line = list(lines_out[cur_line])
                    if (line_pos) >= len(line):
                        line.append(char)
                    else:
                        #if line[line_pos] != ' ':
                        #    print("Replace", repr(line[line_pos]) , "with", repr(char))
                        line[line_pos] = char
                    lines_out[cur_line] = "".join(line)

                    if char not in ['\n', '\r']:
                        line_pos += 1

            else:
                args[:] = [int(x) for x in args]

                if typ == 'A':
                    if not len(args):
                        # Incomplete
                        continue

                    n = args[0]

                    if cur_line - n < 0: # Need to shift
                        cur_line = 0
                    else:
                        cur_line -= n
                    assert(cur_line >= 0)

                elif typ == 'B':
                    if not len(args):
                        # Incomplete
                        continue
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

                elif typ == 'C': # Move right
                    n = 1 # Default move 1
                    if len(args):
                        n = args[0]

                    line_pos += n
                    if line_pos > len(lines_out[cur_line])-1:
                        line_pos = len(lines_out)-1
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

                    # HURISTIC-y hack: linux loves to have a line 123456 then do K(0) 6\r\n
                    # so if the next line is text and the text is [eol]\r\n where [eol] matches the end of this
                    # line - align cur_pos
                    if len(reformatted) > idx+1: # Have another message
                        (next_typ, next_args) = reformatted[idx+1]
                        if next_typ == 'text':
                            if '\r\n' in next_args[0]:
                                next_lines = next_args[0].split("\r\n")
                                if lines_out[cur_line].strip().endswith(next_lines[0]):
                                    # Its the buggy case. Just align it such that we clear the text
                                    # that's about to get echoed
                                    line_pos = line_pos - len(next_lines[0])

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
                
                elif typ == 'm':
                    pass

                elif typ == 's':
                    store_ptr = (cur_line, line_pos)
                elif typ == 'u':
                    (cur_line, line_pos) = store_ptr

                else:
                    raise ValueError(f"Unsupporte ANSI command {typ}")
            #_dump(lines_out, cur_line, line_pos)

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

                # Translate the sofar buffer into plaintext, then determine if we're finished (bc we see new prompt)
                # note this drops the echo'd command
                plaintext = self.unansi(sofar)
                # Now we have command\nresults..........\nprompt

                lines = [x.replace("\r", "") for x in plaintext.split("\n")]
                if len(lines):
                    # Check last line to see if it ends with prompt (indicating we finished)
                    if self.expectation_ends_re.match(lines[-1]) != None:
                        self.last_prompt = lines[-1]
                        lines = lines[:-1]

                        # Drop command we sent - note it won't be a direct match with last_cmd because of weird escape codes
                        # which are based on guest line position when printed - i.e., it would only be an exact
                        # match if we knew and included the prompt when the command was run. Let's just always drop it
                        if len(lines) > 1:
                            lines = lines[1:]
                        else:
                            lines = []

                        self.logfile.flush()
                        if not self.quiet: sys.stdout.flush()

                        plaintext = "\n".join(lines)
                        return plaintext

        if not self.running: # Aborted
            return None

        self.logfile.flush()
        if not self.quiet: sys.stdout.flush()

        self.sofar = sofar.decode('utf8')
        raise TimeoutExpired(f"{self.name} Read message \n{self.sofar}\n")

    def send(self, msg):
        if not self.quiet:
            print(f"{self.name}: send {msg}")
        if not self.consumed_first: # Before we send anything, consume header
            pre = self.expect("")
            self.consumed_first = True

        # Newlines will call problems
        assert len(msg.decode().split("\n")) <= 2, "Multiline cmds unsupported"
        self.last_msg = msg.decode().replace("\n", "")
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

