
from buffer import Buffer
import numpy as np

typa = ["h", "m", "i", "l", "gr", "gs", "u", "c", "r"]


class Tubtf:

    def read_header(self):
        self.buf.goto(0)
        self.version = self.buf.get_u32()
        self.colw = self.buf.get_u32()
        self.contents = self.buf.get_u64()
        self.num_rows = self.buf.get_u32()
        if self.debug:
            print "Trace version = %d  contents = 0x%x  num_row = %d" % (self.version, self.contents, self.num_rows)

    def read_matrix(self):
        dt = np.dtype( [ ('cr3', '<u8'), ('pc', '<u8'), ('type', '<u8'), ('arg1', '<u8'), ('arg2', '<u8'), ('arg3', '<u8'), ('arg4', '<u8')] )
        fp = open(self.filename, "rb")
        fp.seek(4+4+8+4) # this is where the matrix begins
        self.trace = np.fromfile(fp, dtype=dt)        

    def __init__(self, filename):
        self.debug = True
        self.filename = filename
        self.buf = Buffer(filename, False)
        self.read_header()
        self.buf.close()
        self.read_matrix()
        self.num_rows = len(self.trace)

    def spit_range(self, start_ind, end_ind):
        assert (start_ind <= end_ind)
        for i in range(start_ind, end_ind+1):
            (cr3, pc, typ, a1, a2, a3, a4) = tuple(self.trace[i])
            print "%d cr3=%8x pc=%8x " % (i, cr3, pc),
            if typ == 31 or typ == 32:
#        arg1 = (a->typ) | ((a->flag & 0xff) << 8) | (a->off << 16);
                a1 = int(a1)
                addr_type = a1 & 0xff
                flag = (0xff00 & a1) >> 8
                off = (0xffff0000 & a1) >> 16
                if flag == 5:
                    print "irrelevant"
                    continue
                # this is the addr
                val = a2
            if typ == 30:
                # entering llvm fn
                print "llvm-fn-entry %d" % a1
            elif typ == 31:
                # dynval load
                print "load  flag=%d typ=%s v=%8x" % (flag, typa[addr_type], val);
            elif typ == 32:
                # dynval store
                print "store flag=%d typ=%s v=%8x" % (flag, typa[addr_type], val);
            elif typ == 33:
                # dynval branch
                print "branch %d" % a1
            elif typ == 34:
                # dynval sel
                print "select %d" % a1
            elif typ == 35:
                # dynval switch
                print "switch %d" % a1
            elif typ == 36:
                # exception
                print "exception"
            else:
                print "typ = %d?" % typ
