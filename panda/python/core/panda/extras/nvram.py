from panda.extras.file_faker import FakeFile, ffi
import logging



def log(key,value):
    with open(f"logs/kvp.txt", "a") as f:
        f.write(key.decode()+"="+value.decode() + "\n")

class KeyValuePair:
    def __init__(self, dictionary = {}):
        self.dictionary = dictionary
    def write(self, inp):
        inp = inp.replace(b'\x00',b'') # no nulls
        if b"=" in inp:
            key,value = inp.split(b"=")
            self.dictionary[key] = value
            print(f"Added pair {key} {value}")
            log(key,value)
        else:
            if len(inp.rstrip()) > 0:
                self.dictionary[inp] = b""
                print(f'Added pair {inp} b""')
            else:
                print(f"We discarded {inp}")

    def __str__(self):
        retstr = b""
        for key in self.dictionary.keys():
            retstr+= key+b"="+self.dictionary[key]+chr(0).encode()
        return retstr
    def __getitem__(self, key):
        if isinstance(key, int):
            if key < self.__len__():
               return self.__str__()[key]
        elif isinstance(key, slice):
            return self.__str__()[key]
        else:
            print(type(key))
    def __iter__(self):
        for i in self.__str__():
            yield i
    def __len__(self):
        return len(self.__str__())

class NVRAM(FakeFile):
    def __init__(self):
        self.logger = logging.getLogger('panda.hooking')
        self.contents = KeyValuePair()
        with open("kvp_new.out") as f:
            for line in f.readlines():
                self.contents.write(line.encode() + b"\x00")
        self.refcount = 0

    def read(self, size, offset):
        
        '''
        Generate data for a given read of size.  Returns data.
        '''
        
        if offset >= len(self.contents):  # No bytes left to read. So we make more!
            return b""
        
        # Otherwise there are bytes left to read
        read_data = self.contents[offset:offset+size]
        if any(i != 0 for i in read_data):
            self.logger.info(f"real data {read_data[0:1000]}")
            if len(read_data) > 1000:
                self.logger.warn(f"attempted to read {len(read_data)} bytes")
        return read_data
    
    def write(self, offset, write_data):
        self.logger.debug(f"write_data: {write_data}")
        print(f"write_data: {write_data}")
        self.contents.write(write_data)
        return len(write_data) #writes always succeed

    def ioctl(self, cmd, arg):
        self.logger.warning(f"got ioctl and it was cmd:{hex(cmd)} arg:{hex(arg)}")

    def stat(self, stat_struct):
        stat_struct.st_dev = 10 # both copied out of linux documentation
        stat_struct.st_ino = 144 
        S_IFBLK = 0o0060000 # block device
        PERM = 0o777 # all the permissions
        stat_struct.st_mode = S_IFBLK | PERM
        stat_struct.st_nlink = 0
        stat_struct.st_uid = 0
        stat_struct.st_gid = 0
        stat_struct.st_rdev = 0 
        stat_struct.st_size = len(self.contents)
        stat_struct.st_blksize = 512
        from math import ceil
        stat_struct.st_blocks = ceil(len(self.contents)/512) 
        st_atim = 0
        st_mtim = 0
        st_ctim = 0
