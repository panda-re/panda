#!/usr/bin/env python2.7
import sys
import numpy
from plog_reader import PLogReader                                                           

uls = {}

def update_uls(tq):
    for tqe in tq:
        if tqe.HasField("unique_label_set"):
            x = tqe.unique_label_set
            uls[x.ptr] = x.label 

def check_range(pc, range):
    r_min,r_max=range
    if (pc >= r_min) and (pc <= r_max):
        return True
    return False


def get_ttok(tq):
    update_uls(tq)
    all_labels = set([])
    tcns = []
    for q in tq:
        tcns.append(q.tcn)
        for l in uls[q.ptr]:
            all_labels.add(l)
    ttok = " ".join([str(x) for x in all_labels])
    return (numpy.mean(tcns), numpy.std(tcns), ttok)

def get_ttoks(filename, pc_range):
    ttoks = {}
    with PLogReader(filename) as plr:
        for m in plr:
            if not check_range(m.pc, pc_range):
                continue
            tq = None
            if m.HasField("tainted_branch"): tq = m.tainted_branch.taint_query
            if m.HasField("tainted_ldst"): tq = m.tainted_ldst.taint_query                       
            if m.HasField("tainted_cmp"): tq = m.tainted_cmp.taint_query
            if not (tq is None):
                (tcnm,tcns,tt) = get_ttok(tq)                
                v = (m.pc,tcnm,tcns,len(tq))
                if not (tt in ttoks):
                    ttoks[tt] = [v]
                else:
                    ttoks[tt].append(v)
    return ttoks


#ttoks = get_ttoks("/home/tleek/git/panda-fuzzing/panda/scripts/taint.plog", \
#                  (0x8048500, 0x80486ef))
ra = (int(sys.argv[2], 16), int(sys.argv[3], 16))
ttoks = get_ttoks(sys.argv[1], ra)



#taint.plog  0x80000000 0x90000000
for tt in ttoks.keys():
    print tt
    for x in ttoks[tt]:
        (pc,m,s,sz) = x
        if s==0:
            print "  pc=%x tcn=%d sz=%d" % (pc, m, sz)
        else:
            print "  pc=%x tcn=(%.1f+/%.1f sz=%d" % (pc, m, s, sz)


