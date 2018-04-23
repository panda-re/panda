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
from verbosity import verbose_off, verbose, vcheck_output, out_args
from run_debian import run_and_create_recording, qemu_binary
from plog_reader import PLogReader

t1 = time.time()

tmpdir = os.getcwd()

verbose_off()

#create recording

(replay_base, arch_data, stdin, fileinput, guest_cmd) = run_and_create_recording()
print "Created recording of [%s] running on guest" % guest_cmd

t2 = time.time()

# this only works for this arch (for now)
assert (arch_data.dir == 'i386-softmmu')


# also, we need to know if input was file or stdin
# and that it can't be both
if (stdin ^ (not (fileinput is None))):
    pass
else:
    if verbose():
        print "You didn't tell me stdin/fileinput."
    # try to deduce stdin / filename
    saw_redirect = len(filter(lambda x: x=='<', guest_cmd)) > 0
    if saw_redirect:
        stdin = True
        if verbose(): print "... I deduced stdin"
        else: print "tainting file input"
    else:
        fileinput = os.path.basename(guest_cmd[-1])        
        if verbose(): print "... I deduced file input [%s]" % fileinput
        else: print "tainting stdin"

#print "\n-----------------------------------------------------------------------------"
print "First pass replay to figure out when to turn on taint (after file opened)"

replay_args = ["-replay", replay_base]
osi_args = ["-os", "linux-32-lava32"]
asidstory_plog = tmpdir + "/asidstory.plog"
try:
    os.remove(asidstory_plog)
except:
    pass
asidstory_args = ["-pandalog", asidstory_plog, "-panda", "asidstory:summary"]
panda_args = replay_args + osi_args + asidstory_args

# first pass to get asids, cmds and instr start /stop
if verbose():
    print "first pass xx " + (" ".join([qemu_binary(arch_data)] + panda_args)) + " xx"


output = vcheck_output([qemu_binary(arch_data)] + panda_args)

#print "wrote %s" % asidstory_plog

t3 = time.time()

binary_basename = os.path.basename(guest_cmd[0])

# look for extent (first, last instr) for the program we ran
first_instr = (10 ** 6) ** 2
last_instr = 0
asids_for_binary = set()
with PLogReader(asidstory_plog) as plr:
    for m in plr:
        if m.HasField("asid_info"):
            ai = m.asid_info
            asid = ai.asid & 0x0fffffff
#            print "%s %x %s..%s" % (ai.name, asid, ai.start_instr, ai.end_instr)
            if ai.name == binary_basename:
                if asid != 0:
                    asids_for_binary.add(asid)
                if first_instr > int(ai.start_instr):
                    first_instr = int(ai.start_instr)
                if last_instr < int(ai.end_instr):
                    last_instr = int(ai.end_instr)                    

print "%s: asids=[" % binary_basename,
for asid in asids_for_binary:
    print "%x," % asid,

print "] extent is instr %d..%d" % (first_instr, last_instr)
#print "\n-----------------------------------------------------------------------------"
print "Second pass replay to scissors"

scissors_replay = replay_base + "_sciss"
pad = 1
panda_args = ["-replay", replay_base, "-panda", "scissors:name=%s,start=%d,end=%d" % (scissors_replay,first_instr-pad,last_instr+pad)]

if verbose():
    print "second pass xx " + (" ".join([qemu_binary(arch_data)] + panda_args)) + " xx"

output = vcheck_output([qemu_binary(arch_data)] + panda_args)
 
t4 = time.time()

#print "\n-----------------------------------------------------------------------------"
print "Third pass replay to actually perform taint analysis"

# second pass to do taint analysis
taint_plog = tmpdir + "/taint.plog"
try:
    os.remove(taint_plog)
except:
    pass
panda_args = ["-replay", scissors_replay] + osi_args + ["-pandalog", taint_plog]

if stdin:
    raise ValueError("Actually, stdin taint not working?")
else: 
    # file input
    more_args =  ["-panda", "file_taint:filename=%s,pos,enable_taint_on_open" % fileinput, \
#                  "-panda", "tainted_instr", \
                  "-panda", "tainted_branch", \
                  "-panda", "edges",
                  "-panda", "tainted_ldst"\
    ]
    panda_args.extend(more_args)


if verbose(): 
    print "third pass xx " + (" ".join([qemu_binary(arch_data)] + panda_args)) + " xx"

output = vcheck_output([qemu_binary(arch_data)] + panda_args)

#print "wrote %s" % taint_plog


t5 = time.time()


uls = {}
def update_uls(tq):
    for tqe in tq:
        if tqe.HasField("unique_label_set"):
            x = tqe.unique_label_set
            uls[x.ptr] = x.label # this is a list I think

def print_tq(tq):
    for tqe in tq:
        print ("tq offs=%d tcn=%d " % (tqe.offset, tqe.tcn)) + (str(uls[tqe.ptr])),
    print " "

tainted_branches = {}
edges = {}

with PLogReader("taint.plog") as plr:
    for m in plr:        
        tq = None
        if m.HasField("tainted_branch"):
            tq = m.tainted_branch.taint_query
            assert (not (tq is None))
            update_uls(tq)
            if m.tainted_branch.is_cond:
                if m.tainted_branch.asid in asids_for_binary:
                    if not (m.pc in tainted_branches):
                        tainted_branches[m.pc] = []
                    tqr = tuple([(tqe.tcn, tqe.offset, uls[tqe.ptr]) for tqe in tq])
                    tainted_branches[m.pc].extend(tqr)
        if m.HasField("asid_edges"):
            ase = m.asid_edges
            asid = ase.asid
            if asid in asids_for_binary:
                for edge in ase.edges:
                    f = edge.begin
                    t = edge.end
                    if not (f in edges):
                        edges[f] = set()
                    edges[f].add(t)
        if m.HasField("tainted_ldst"):
            print "TLDST @ pc %x" % m.pc


for f in edges.keys():
    if len(edges[f]) == 1:
#        print "HCC %x" % f
        if f in tainted_branches:
            print "THCC @ pc %x %s" % (f, str(tainted_branches[f]))
        
        
            

#for line in output.split('\n'):
#    print line

d1 = t2-t1  # time to create recording
d2 = t3-t2  # time to run asidstory 
d3 = t4-t3  # time to create scissors
d4 = t5-t4  # time to replay with taint
s2 = d2/d1  # slowdown of replay + asidstory vs record
s3 = d3/d1  # slowdown of scissors vs record
s4 = d4/d1  # slowdown of taint (on scissors) vs record
#print
print "%.2f sec: recording" % d1
print "%.2f sec: 1st replay (asidstory) slowdown %.2f" % (d2, s2)
print "%.2f sec: 2nd replay (scissors) slowdown %.2f" % (d3, s3)
print "%.2f sec: 3rd replay (taint) slowdown %.2f" % (d4, s4)
print " "

