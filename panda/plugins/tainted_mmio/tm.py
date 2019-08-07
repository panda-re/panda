#
# This script reads the pandalog generated when we run tainted_mmio and collect_code  plugins
# It produces the kind of output in tm.out.
#
# For each tainted mmio read while panda is running, we apply taint
# labels to the data read. Then, we output a plog entry for each
# tainted instruction or tainted branch, noting which labels it
# involves.  In this script, we collect, for each tainted MMIO read,
# the sequence of subsequent instructions that involve it. Those are
# displayed as labeled basic blocks of disassembly (each instruction
# involving that label gets a star).
#
# Note: we can easily (and do) encounter the same instruction that is
# a read of MMIO data more than once.  If so, we output two traces as
# described above.
#
# Here is cmdline I used to generate plog...
#  ~/git/panda-taintedmmio/build/arm-softmmu/qemu-system-arm -kernel /home/tleek/git/holodeck/firmwares/turris_omnia/omnia-kernel-4.4.138-zImage -initrd /home/tleek/git/holodeck/firmwares/turris_omnia/omnia-initramfs-modded.cpio -append "console=ttyS0,115200 debug lpj=10000 rootfstype=ext4 root=/dev/vda1" -cpu cortex-a9 -nographic  -panda holodeck:config=/home/tleek/git/panda-taintedmmio/panda/plugins/holodeck/config.yaml  -panda tainted_mmio:uninit=1 -panda tainted_instr -panda tainted_branch -panda collect_code
# 
#
# usage: tm.py plog 


import sys
import cPickle as pickle
sys.path.append("../../scripts")

from intervaltree import Interval, IntervalTree
from capstone import *

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

plog = sys.argv[1]

from plog_reader import PLogReader

uls = {}
seq = {}
ioaddr = {}
ct = IntervalTree()
bbs = {}

def process_uls(tqs):
    for tq in tqs:
        try:
            u = tq.unique_label_set
            uls[u.ptr] = [x for x in u.label]
        except:
            pass




class BasicBlock:

    def __init__(self, asid, pc, size, code):
        self.asid = asid
        self.pc = pc
        self.size = size
        self.end_pc = pc + size - 1
        self.code = code

saveit = True

# this code will let you only optionally read pandalog during
# debugging (speedy). disabling for commit
if (len(sys.argv) == 3) and (sys.argv[2] == 'saveit'):
    saveit = True


if saveit:
    print("Reading pandalog")
    with PLogReader(plog) as plr:
        for i, m in enumerate(plr):
            if (i%100000) == 0:
                print("Log entry %d" % i)

            if m.HasField('basic_block'):
                bb = m.basic_block
                if bb.pc > 0:
                    interv = Interval(bb.pc, bb.pc + bb.size)
                    ct.add(interv)
                    bbs[interv] = bb.code

            if m.HasField('tainted_mmio_label'):
                t = m.tainted_mmio_label
                label = t.label
                ioaddr[label] = t.addr

            tqs = None

            if m.HasField('tainted_branch'):
                tqs = m.tainted_branch.taint_query

            if m.HasField('tainted_instr'):
                tqs = m.tainted_instr.taint_query

            if not (tqs is None):
                process_uls(tqs)
                for tq in tqs:
                    ptr = tq.ptr
                    for l in uls[ptr]:
                        if not (l in seq):
                            seq[l] = [m.pc]
                        else:
                            if m.pc != seq[l][-1]:
                                seq[l].append(m.pc)



if saveit:
    print("Pickling things")
    with open("tm.pk", "w") as p:
        everything = [uls, seq, ioaddr, ct, bbs]
        pickle.dump(everything, p)
#        pickle.dump(seq, p)
#        pickle.dump(ioaddr, p)
#        pickle.dump(ct, p)
#        pickle.dump(bbs, p)
else:
    print("Unpickling things")
    with open("tm.pk", "r") as pick:
        [uls, seq, ioaddr, ct, bbs] = pickle.load(pick)



sl_hist = {}
        
for l in seq:
    print "\n------------------------------------------------------------------"
    print "label=%d ioaddr=%x (len(seq)=%d) : " % (l, ioaddr[l], len(seq[l])),
    sl = len(seq[l])
    if not sl in sl_hist:
        sl_hist[sl] = 1
    else:
        sl_hist[sl] += 1
    if sl < 200:
        i = 0
        ls = len(seq[l])
        pcs = []
        bbint_last = None
        def spit(bbint_last, bbint_curr, pcs):
            if bbint_last is None: return False
            if bbint_curr is None:
                pass
            else:
                if bbint_last == bbint_curr: return False
            print("\nPCs: "),
            for pc in pcs:
                print ("%x " % pc),
            print "\nBB:"

            for instr in md.disasm(bbs[bbint_last], bbint_last.begin):
                if instr.address in pcs:
                    print("T "),
                else:
                    print("  "),
                print "0x%x:\t%s\t%s" %(instr.address, instr.mnemonic, instr.op_str)            
            return True
        while i<ls:
            pc = seq[l][i]
            bbint_curr = ct.search(pc)
            bbint_best = None
            for bbint in bbint_curr:
                if bbint_best is None:
                    bbint_best = bbint
                if bbint.contains_interval(bbint_best):
                    bbint_best = bbint
            if (spit(bbint_last, bbint_best, pcs)):
                pcs = []
            pcs.append(pc)
            i=i+1
            if i == ls:
                spit(bbint_best, None, pcs)
            bbint_last = bbint_best

    else:
        print "len(seq) > 100"        
    print 


sls = sl_hist.keys()
sls.sort()
for sl in sls:
    print "sl=%d c=%d" % (sl, sl_hist[sl])
