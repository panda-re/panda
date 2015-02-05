#!/usr/bin/env python

##  @file kernelinfo_parse.py
#   @brief Script for retrieving the last kernelinfo block from dmesg.
#   The printout format is suitable for appending to a kernelinfo.conf file.
#
#   @copyright  This work is licensed under the terms of the GNU GPL, version 2.
#               See the COPYING file in the top-level directory. 
#   @author Manolis Stamatogiannakis <manolis.stamatogiannakis@vu.nl>

from __future__ import print_function
import subprocess
import re
import sys

start = 'KERNELINFO-BEGIN'
end = 'KERNELINFO-END'
inblock = False
proc = subprocess.Popen(['dmesg',],stdout=subprocess.PIPE)

# Retrieve the last block of kernel information lines.
for line in proc.stdout:
    if start in line:
        inblock = True
        lines = []
        continue
    elif end in line:
        inblock = False
        continue
    elif inblock:
        lines.append(line)

# Process lines.
trans = lambda s: re.sub(r'^\[[^]]*\]\s+', '', s)
lines = map(trans, lines)

if not lines:
    sys.exit(1)

# Get and parse the name line.
name_grep = lambda l: re.match(r'^\s*name\s*=', l)
kname = filter(name_grep, lines)[-1].split('=', 1)[1].strip().lower()
kcomponents = re.split(r'\s+', kname)

# Find the version component of the name line.
version_idx=-1
for i, val in enumerate(kcomponents):
    if re.match(r'^[23]\.[0-9]*', val):
        version_idx = i
        break

# Print group line.
print('[%s-%s-%s]' % (
    kcomponents[version_idx-1],
    re.split(r'[^0-9.]*', kcomponents[version_idx])[0],
    kcomponents[-1]
))

# Print key-value pairs.
print(''.join(lines), end="")

