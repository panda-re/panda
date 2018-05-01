#!/usr/bin/env python2.7
"""This should work with same cmdline as run_debian.py.  

Create recording of 32-bit linux program and replay it, tainting input
and querying taint on instructions and branches, outputing a pandalog.

Usage really should be same as run_debian.py

So, e.g., the following should work

% python taint_debian.py foo /etc/passwd
% python taint_debian.py guest:base64 /etc/passwd

The first will create recording of running the binary 'foo' which is
assumed to be in the path and a 32-bit linux executable.

The second will create a recording of running the program 'base64'
assumed to exist on the guest and be in the path.

In either case the input to the program is the guest's /etc/passwd
file.

The important output of this script is a pandalog which contains
results of all the tainted_branch and tainted_instr queries.  That
output goes in a std place: taint.plog.  You can read this file with
plog_reader.py, or you can use that script as a template for writing
your own analysis.

Notes

1. There's some dodgy magic trying to figure out if input is file or
stdin.  This is bc we need to tell the taint system when we replay.

2. The script runs the replay under panda twice. Once, with the taint
system disabled, to determine where the file or stdin is opened,
i.e. what instruction count. Second run we use that instr count to
know when to turn on taint system (which is slow).

3. After that second run of panda, with taint turned on, the script
prints out all the output of panda which you should inspect to make
sure the replay got to the end and labels were applied, etc.

4. Whatever gets taint-labeled gets what we call 'positional' labels,
meaning the first byte labeled gets label 0, the second byte gets
label 1, etc.  These may correspond to byte positions in a file.

5. The taint queries done by the tainted_instr plugin work as
follows. When the taint system detects that something has changed in
its shadow memory due to a copy or computation (not a deletion), every
byte in the result of that change is queried to learn how it is
tainted.  The results of each of those queries is sent to the
pandalog, indicating what labels taint that value as well as the
overall taint compute number of the result.

6. The taint queries done by the tainted_branch are simpler.  Whenever
there is a branch that depends upon tainted data, every byte in the
register used to decide that branch is queried to learn how it is
tainted.  The results of each of those queries also go to the pandalog.

7. Ok, 5 & 6 are actually a little more subtle. Since the taint system
operates at the llvm level, taint changes and branches are identified
at that level.  This means you might see multiple tainted_instr
entries for the same pc.  There should be just one tainted_branch
entry for a single pc, though.

"""

import re
import os
import subprocess32 as sp
import time
from run_debian import run_and_create_recording, qemu_binary

t1 = time.time()

#create recording
(replay_base, arch_data, stdin, fileinput, guest_cmd) = run_and_create_recording()

t2 = time.time()

# this only works for this arch (for now)
assert (arch_data.dir == 'i386-softmmu')


# also, we need to know if input was file or stdin
# and that it can't be both
if (stdin ^ (not (fileinput is None))):
    pass
else:
    print "You didn't tell me stdin/fileinput."
    # try to deduce stdin / filename
    saw_redirect = len(filter(lambda x: x=='<', guest_cmd)) > 0
    if saw_redirect:
        stdin = True
        print "... I deduced stdin"
    else:
        fileinput = os.path.basename(guest_cmd[-1])        
        print "... I deduced file input [%s]" % fileinput

print "\n-----------------------------------------------------------------------------"
print "\nFirst pass replay to figure out when to turn on taint (after file opened)\n"

base_panda_args = ["-replay", replay_base, "-os", "linux-32-lava32"]
panda_args = list(base_panda_args)

# replay to figure out where to turn on taint
if stdin:
    raise ValueError("Actually, stdin taint not working?")
else: 
    # file input
    panda_args.extend(["-panda", "file_taint:filename=%s,notaint=y" % fileinput])

# first pass to get instr to turn on taint
output = sp.check_output([qemu_binary(arch_data)] + panda_args)

t3 = time.time()

for line in output.split('\n'):
#    print line
    foo = re.search("saw open of file we want to taint: .* insn ([0-9]+)", line)
    if foo:
        insn = int(foo.groups()[0])
        print "file opened @ insn = %d" % insn
        print "arbitrarily reducing that by 1m"
        insn -= 1000000
        if insn < 0:
            insn = 0
        break
        print "We'll turn on taint around instr %d" % insn


print "\n-----------------------------------------------------------------------------"
print "\nSecond pass replay to actually perform taint analysis\n"

# second pass to
panda_args = list(base_panda_args)
panda_args.extend(["-pandalog", "taint.plog"])

if stdin:
    raise ValueError("Actually, stdin taint not working?")
else: 
    # file input
    more_args =  ["-panda", "file_taint:filename=%s,pos=y,first_instr=%d" % (fileinput, insn), \
                  "-panda", "tainted_instr", \
                  "-panda", "tainted_branch"]
    panda_args.extend(more_args)

# first pass to get instr to turn on taint
output = sp.check_output([qemu_binary(arch_data)] + panda_args)

t4 = time.time()

for line in output.split('\n'):
    print line

d1 = t2-t1
d2 = t3-t2
d3 = t4-t3
r1 = d2/d1  # slowdown of replay vs record (mostly)
r2 = d3/d1  # slowdown of replay with taint vs record
print
print "%.2f sec: recording" % (t2-t1)
print "%.2f sec: first replay          (slowdown wrt record: %.2f)" % (t3-t2, r1)
print "%.2f sec: second (taint) replay (slowdown wrt record: %.2f)" % (t4-t3, r2)


