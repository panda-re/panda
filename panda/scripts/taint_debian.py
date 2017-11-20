
"""This should work with same cmdline as run_debian.py.  

Idea is to create recording and replay it, tainting input and querying
taint on instr and branches, creating a pandalog.

Note: there's some dodgy magic trying to figure out if input is file
or stdin.  This is bc we need to tell the taint system when we replay.

The script runs the replay under panda twice. Once, with the taint
system disabled, to determine where the file or stdin is opened,
i.e. what instruction count. Second run we use that instr count to
know when to turn on taint system (which is slow).

After that second run of panda, with taint turned on, the script
prints out all the output of panda which you should inspect to make
sure the replay got to the end and labels were applied, etc.

The real output of this script is a pandalog which contains results of
all the tainted_branch and tainted_instr queries.  That output goes in
a std place: taint.plog.  You can read this file with plog_reader.py,
or you can use that script as a template for writing your own
analysis.

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
    panda_args.extend(["-panda", "file_taint:filename=%s,notaint" % fileinput])

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
    more_args =  ["-panda", "file_taint:filename=%s,pos,first_instr=%d" % (fileinput, insn), \
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


