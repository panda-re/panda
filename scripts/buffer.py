import os
import struct
import string
import gzip


class BufferEmpty(Exception):
    pass


class Buffer:

    def __init__(self, filename, gz):
        if gz:
            self.fp = gzip.open(filename)
        else:
            self.fp = open(filename, "rb")
        self.ind = 0
        self.len = int(os.path.getsize(filename))

    def close(self):
        self.fp.close()

    def read(self, n):
        buf = self.fp.read(n)
        if buf == '':
            raise BufferEmpty
        else:
            return buf
        
    def get_u64(self):        
        buf = self.read(8)
        x = struct.unpack("Q", buf)
        self.ind += 8
        return x[0]

    def get_u32(self):
        buf = self.read(4)
        x = struct.unpack("I", buf)
        self.ind += 4
        return x[0]

    def get_u8(self):
        buf = self.read(1)
        x = struct.unpack("B", buf)
        self.ind += 1
        return x[0]

    def get_int(self):
        return self.get_u32()

    # actually, we'll return label set as a list
    def get_labelset(self):
        typ = self.get_u32();
        tainted_val_num = self.get_u64();
        max_size = self.get_int();
        current_size = self.get_int();
        labels = []
        for i in range(current_size):
            labels.append(self.get_int())
        return (typ, tainted_val_num, frozenset(labels))

    def get_md5(self):
        md5_str = ""
        for i in range(4):
            md5_str += "%08x" % (self.get_u32())
        return md5_str

    def get_itvd(self):
        kind = self.get_u32()
        val = self.get_u32()
        size = self.get_u32()
        eip = self.get_u32()
        if kind == 0:
            # not tainted
            return (kind, val, size, eip)
        elif kind == 1:
            # base value
            num = self.get_u32()
            l = self.get_u32()
            labelstr = self.get_str_n(l)
            return (kind, val, size, eip, num, labelstr)
        elif kind == 2:
            # composed
            op_num = self.get_u32()
            arg1 = self.get_md5()
            arg2 = self.get_md5()
            arg3 = self.get_md5()
            arg4 = self.get_md5()
            return (kind, val, size, eip, op_num, arg1, arg2, arg3, arg4)
        elif kind == 3:
            # tv copy
            arg1 = self.get_md5()
            ind1 = self.get_u32()
            arg2 = self.get_md5()
            ind2 = self.get_u32()
            arg3 = self.get_md5()
            ind3 = self.get_u32()
            arg4 = self.get_md5()
            ind4 = self.get_u32()
            arg5 = self.get_md5()
            ind5 = self.get_u32()
            arg6 = self.get_md5()
            ind6 = self.get_u32()
            arg7 = self.get_md5()
            ind7 = self.get_u32()
            arg8 = self.get_md5()
            ind8 = self.get_u32()
            return (kind, val, size, eip, arg1, ind1, arg2, ind2, arg3, ind3, arg4, ind4, arg5, ind5, arg6, ind6, arg7, ind7, arg8, ind8)
        else:
            assert (1==0)

    def get_itri(self):
        type = self.get_int()
        arg = self.get_int()
        num = self.get_int()
        pc = self.get_int()
        pos = self.get_int()
        itri = (type, arg, pc, pos)
        return itri

    def get_str_n(self, n):
        str = self.read(n);
        self.ind += n
        return str

    def get_iap(self):
        command = self.get_str_n(16)
        command = filter(lambda x: x in string.printable, command)
        pc = self.get_int()
        type = self.get_int()
        arg = self.get_int()
        offset = self.get_int()
        iap = (command, pc, type, arg, offset)
        return iap

    def get_string(self):
        len = self.get_int()
        x = self.read(len)
        self.ind += len
#        x = self.buf[self.ind : self.ind + len]
        return x

    def __len__(self):
        return self.len

    def pos(self):
        return self.ind

    def goto(self, ind):
        self.fp.seek(ind)
        self.ind = ind

    def eof(self):
        return (self.len == self.ind)

    def frac(self):
        return self.ind / (float(self.len))
