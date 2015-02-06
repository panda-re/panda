#!/usr/bin/env python
#
# Normalizer for osi_test output.
#
# Assumption: after the end of a process/lib list, some
# other line must follow *before* the next heading line.

from __future__ import print_function
import fileinput
import re

PROCS_HEAD_RE = r'\(([0-9]+) procs\)'
PROCS_LIST_RE = r'\s+(\S+)\s+([0-9]+)\s+([0-9]+)'
LIBS_HEAD_RE = r'\(([0-9]+) libs\)'
LIBS_LIST_RE = r'\s+(0x[0-9a-f]+)\s+([0-9]+)\s+(\S+)\s+(\S+)'

PROCS_HR = 3*'*' + "%04d" + 33*'*'
LIBS_HR = 3*'%%' + "%04d" + 33*'%%'

IN_PROCESS_LIST = False
IN_LIBRARY_LIST = False

nproclist = 0
nliblist = 0

for line in fileinput.input():
    if IN_PROCESS_LIST:
        m = re.match(PROCS_LIST_RE, line)
        if m:
            # print a normalized line
            t = (m.group(1), int(m.group(2)), int(m.group(3)))
            print(*t)
            procset.add(t)
        else:
            assert (len(procset) == nproc), "Process list length mismatch."
            IN_PROCESS_LIST = False
            print(PROCS_HR % (nproclist))
            nproclist += 1
    #-------------------------------------------------------
    elif IN_LIBRARY_LIST:
        m = re.match(LIBS_LIST_RE, line)
        if m:
            # print a normalized line
            t = (m.group(1), int(m.group(2)), m.group(3), m.group(4))
            print(*t)
            libset.add(t)
        else:
            assert (len(libset) == nlib), "Library list length mismatch."
            IN_LIBRARY_LIST = False
            print(LIBS_HR % (nliblist))
            nliblist += 1
    #-------------------------------------------------------
    else:
        # check for process list heading
        m = re.search(PROCS_HEAD_RE, line)
        if m:
            IN_PROCESS_LIST = True
            nproc = int(m.group(1))
            procset = set()
            print(PROCS_HR % (nproclist))

        # check for library list heading
        m = re.search(LIBS_HEAD_RE, line)
        if m:
            IN_LIBRARY_LIST = True
            nlib = int(m.group(1))
            libset = set()
            print(LIBS_HR % (nliblist))
