#!/usr/bin/env python

debug = False

# takes pandalog as single paaram.  
# runs pandalog_reader on it and then consumes the output to produce an ascii viz of process births and deaths

import subprocess as sb
import sys
import re
import os
import fileinput

# have pandalog_reader parse the pandlog 
plogfile = os.path.realpath(sys.argv[1])
pandalog_print = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/../panda/pandalog_reader")
p = sb.Popen([pandalog_print, plogfile], stdout=sb.PIPE, stderr=sb.PIPE)
(pplog,e) = p.communicate()


def setc (x, y, c, oblit):
    global cells
    if not (y in cells):
        cells[y] = {}
    if not (x in cells[y]) or oblit:
        cells[y][x] = c

def text(x, y, text, blit):
    global cells
    for c in text:
        setc(x, y, c, blit)
        x += 1

def hline(x1, x2, y):
    global cells
    for x in range(x1, x2+1):
        setc(x, y, '-', False)
            
def vline(x, y1, y2):
    if debug:
        print "vline %d %d -> %d" % (x, y1, 2)
    global cells
    for y in range(y1, y2+1):
        if not (y in cells):
            cells[y] = {}
        if x in cells[y]:
            if cells[y][x] == '-':
                cells[y][x] = '|'
        else:            
            setc(x, y, '|', False)
    

width = 80
cells = {}

    

class Mm:

    def __init__(self, val):
        self.val = val
        self.min = val
        self.max = val

    def update(self, newval):
        if newval > self.max:
            self.max = newval
        if newval < self.min:
            self.min = newval
            

# track number of times we've seen unique pid for same full proc name
namecount = {}
# map from name/pid -> shortname            
snamem = {}
shortnamecount = {}
# set of currently running processes in mid plog processing
running = set([])

class Proc:

    def __init__(self, pid, fullname, name):
        self.pid = pid
        self.fullname = fullname
        self.name = name
        np = (self.pid, self.fullname)
        if np in snamem:
            # we already know the short name 
            sn = snamem[np]
        else:
            # construct a new short name
            sn = name[:10]            
            if not (sn in shortnamecount):
                shortnamecount[sn] = 0
            shortnamecount[sn] += 1
            sn += (str(shortnamecount[sn]))
            snamem[np] = sn
        self.shortname = sn
        self.first_instr = Mm(0)
        self.last_instr = Mm(0)
        self.birthday = None
        self.deathday = None
        self.parent = None
        self.children = []
        self.boring = False
        
    def __eq__(self, other):
        return (self.pid == other.pid) and (self.fullname == other.fullname)

    def __hash__(self):
        p = (self.pid, self.fullname)
        return (hash(p))
    
    def sighted(self, instr):
        self.first_instr.update(instr)
        self.last_instr.update(instr)

    def __str__(self):
        foo = "%11s %d-%s" % (self.shortname, self.pid, self.fullname)
        if not self.boring:
            if not (self.birthday is None):
                foo += "-b%d" % self.birthday
            else:
                foo += "-%d" % self.first_instr.min
            if not (self.deathday is None):
                foo += "-d%d" % self.deathday
            else:
                foo += "-%d" % self.last_instr.max
            if self.parent:
                foo += "-p-%s" % (ind2proc[self.parent].shortname)
        return foo
        
# map from proc to ind number
ind2proc = {}
proc2ind = {}
# map from name/pid to ind in ind2proc
running_procs = {}

def get_proc_ind(pid, fullname):
    global ind2proc
    global proc2ind
    global running_procs 
    # pathological situation
    if pid <= 0:
        pid = 0
        name = "unknown"
    # clean up name a little
    fullname = fullname.strip(')')
    name = fullname
    foo = re.search("(.*).exe", name)
    if foo:
        name = foo.groups()[0]
    else:
        foo = re.search("(.*).dll", name)
        if foo:
            name = foo.groups()[0]
        else:
            foo = re.search("(.*).dll", name)
            if foo:
                name = foo.groups()[0]
    np = (name, pid)
    # is it a currently running process
    if np in running_procs:
        return running_procs[np]
    # not in running procs --
    # 1. birth
    # 2. first sighting (but not birth)
    # 3. rebirth (pid / name reused)
    proc = Proc(pid, fullname, name)
    ind = len(ind2proc)
    ind2proc[ind] = proc
    proc2ind[proc] = ind
    running_procs[np] = ind
#    print "not a running proc ind=%d -- added.  now %d running" % (ind, len(running_procs))
    
    return ind


def seen(curr, instr):
    ind2proc[curr].sighted(instr)

def birth(parent, child, instr):
    if debug:
        print "birth "
        print "parent -- %s ind=%d" % (str(ind2proc[parent]), parent)
        print "child  -- %s ind=%d" % (str(ind2proc[child]), child)
    seen(parent, instr)
    seen(child, instr)
    ind2proc[child].parent = parent
    ind2proc[child].birthday = instr
    ind2proc[child].first_instr.min = instr
    ind2proc[parent].children.append(child)        
    if debug:
        print "%d running procs" % (len(running_procs))
    
def terminate(killer, killed, instr):
    if debug:
        print "terminate"
        print "killer -- %s ind=%d" % (str(ind2proc[killer]), killer)
        print "killed  -- %s ind=%d" % (str(ind2proc[killed]), killed)
    seen(killer, instr)
    seen(killed, instr)
    ind2proc[killed].deathday = instr    
    tp = ind2proc[term]
    tnp = (tp.name, tp.pid)
    running_procs.pop(tnp)
    if debug:
        print "%d running procs" % (len(running_procs))
    



    
max_instr = None

ii = 0
instrs = Mm(0)
for line in pplog.split("\n"):
#for line in fileinput.input():    
#    print line
    foo = re.search("instr=[0-9]+ pc=0x[0-9a-f]+ : total instr ([0-9]+)", line)
    if foo:
        max_instr = int(foo.groups()[0])
        if debug:
            print "max_instr = %d" % max_instr
    foo = re.search("instr=([0-9]+) pc=0x[0-9a-f]+ : nt_create_user_process (.*)$", line)
    if foo:
        y = foo.groups()[1].split()
        parent = get_proc_ind(int(y[3].strip(',')), y[4])
        child = get_proc_ind(int(y[9].strip(',')), y[10])
        instr = int(foo.groups()[0])
        birth(parent, child, instr)        
    foo = re.search("instr=([0-9]+) pc=0x[0-9a-f]+ : nt_terminate_process (.*)$", line)
    if foo:
        y = foo.groups()[1].split()
        curr = get_proc_ind(int(y[3].strip(',')), y[4])
        term = get_proc_ind(int(y[9].strip(',')), y[10])
        instr = int(foo.groups()[0])
        terminate(curr, term, instr)
    foo = re.search("instr=([0-9]+) pc=0x[0-9a-f]+ .* new_pid, ([0-9]+), (.*)\)", line)
    if foo:
        curr = get_proc_ind(int(foo.groups()[1]), foo.groups()[2].strip(')'))
        instr = int(foo.groups()[0])
        seen(curr, instr)

if debug:
    print "processed entire plog"


# any process for which we haven't seen death is assume to last entire replay
n = len(ind2proc)
for i in range(n):
    if ind2proc[i].deathday is None:
        ind2proc[i].last_instr.update(max_instr)
    if ind2proc[i].birthday is None:
        ind2proc[i].first_instr.update(0)


sc = width / (float(max_instr - instrs.min))


# get subset of inds that are processes that were not created during this replay
# i.e. predated this replay
preexisting = []
for i in range(n):
    proc = ind2proc[i]
    if proc.parent is None:
        preexisting.append(proc)
# and sort them by first instr
spreexisting = sorted(preexisting, key=lambda proc: proc.first_instr.min)


def print_proc(f, proc, indent):
    f.write ( "  " * indent )
    if proc.boring is True:
        f.write (" [b] ")
    else:
        f.write (" [i] ")
    f.write((str(proc)) + "\n")
    for cind in proc.children:
        print_proc(f, ind2proc[cind], indent+1)
        

def render_proc(proc):
    global row
    global sname
    if debug:
        print "render_proc : " + (str(proc)) + " " + str(row)    
    # no reason to render a proc if it exists for entire
    # trace *unless* it has children
    if (proc.first_instr.min == 0 and proc.last_instr.max == max_instr):
        if debug:
            print "-- spans entire replay"
        if (len(proc.children) == 0):
            if debug:
                print "-- has no chlidren"
            proc.boring = True
            return        
    start = int(proc.first_instr.min * sc)
    end = int(proc.last_instr.max * sc)
    if debug:
        print "start,end = %d,%d" % (start, end)
    hline(2+start, 2+end, row)
    if (proc.parent is None):
        setc(2+start, row, '?', True)
    else:
        setc(2+start, row, 'C', True)
    if (proc.deathday is None):
        setc(2+end, row, '?', True)
    else:
        setc(2+end, row, 'T', True)            
    sname[row] = proc.shortname
    row += 1
    children = []
    if debug:
        print "%s has %d children" % (proc.shortname, len(proc.children))
    for cind in proc.children:
        child = ind2proc[cind]
        if debug:
            print child
        children.append(child)
    if len(children) > 0:
        if debug:
            print "%s has %d children" % (proc.shortname, len(children))
        prow = row
        # sort them by first instr too and render
        schildren = sorted(children, key=lambda p: p.first_instr.min)    
        for child in schildren:
            x = 2+int (child.first_instr.min * sc)
            vline(x, prow, row-1) 
            setc(x, prow-1, '+', True)
            render_proc(child)





row = 0
sname = {}
for proc in spreexisting:
    render_proc(proc)
num_rows = row    



f = open("procstory", "w")
f.write ("max_instr = %d\n" % max_instr)
f.write( "==========================================\n")
indent = 0
for proc in spreexisting:
    print_proc(f, proc, indent)

f.write ("Note: A process is either [b]oring or [i]nteresting. It is boring iff\n")
f.write ("        (1) we did not see its creation,\n")
f.write ("        (2) we did not see its termination,\n")
f.write ("    and (3) it has no children\n")
f.write( "==========================================\n")    



vline(1, 0, num_rows)
vline(3+width, 0, num_rows)

for v in range(num_rows):
    if v in sname:
        f.write( "%11s : " % sname[v])
    else:
        f.write( "%11s   " % " ")
    for h in range(width+5):
        if not (v in cells):
            f.write(" ")
        else :
            if h in cells[v]:
                f.write( cells[v][h] )
            else:
                f.write (' ')
    f.write("\n")
f.write( "==========================================\n")    
f.write("Legend: [C]reation [T]ermination [?]Unknown [+]Branch\n")
f.close()


f = open("procstory")
for line in f.readlines():
    print line,

