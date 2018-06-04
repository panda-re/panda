import struct
from google.protobuf.json_format import MessageToJson
import sys
import os
from os.path import dirname, join, realpath
import zlib
import struct
from enum import Enum, IntEnum


panda_dir = "/home/raywang/panda"
def try_path(*args):
    args = list(args) + ['i386-softmmu']
    build_dir = join(*args)
    if os.path.isdir(build_dir):
        sys.path.append(build_dir)
try_path(panda_dir, 'build')
try_path(panda_dir)
try_path(dirname(panda_dir), 'opt-panda')
try_path(dirname(panda_dir), 'debug-panda')
import plog_pb2

class PandaLog:
    def __init__(self, filename, mode):
        self.chunks = self.read_dir(filename)
        self.read_mode = mode
        self.entries = {}
        self.version, self.dir_pos, self.chunk_size = 0, 0, 0
        # These params are reading bwd right now
        self.cur_index = -1
        self.cur_chunk = len(self.chunks)-1

    def read_dir(self, fn):
        self.f = open(fn)

        self.version, _, self.dir_pos, _, self.chunk_size = struct.unpack('<IIQII', self.f.read(24))

        self.f.seek(self.dir_pos)
        num_chunks = struct.unpack('<I', self.f.read(4))[0]
        print num_chunks

        entries = []
        for i in range(num_chunks):
            buf = self.f.read(24)
            entries.append(struct.unpack('<QQQ', buf))

        if entries[-1][1] != self.dir_pos:
            entries.append((0, self.dir_pos, 0))
        return entries
    
    def unmarshall_chunk(self, chunk_num):
        self.entries[chunk_num] = []
        this_chunk_entry = self.chunks[chunk_num]
        next_chunk_entry = self.chunks[chunk_num+1]

        print "unmarshalling chunk", chunk_num 
        start_instr, start_pos, num_entries = this_chunk_entry
        next_pos = next_chunk_entry[1]
        self.f.seek(start_pos)
        zsize = next_pos - start_pos

        zdata = self.f.read(zsize)
        data = zlib.decompress(zdata, 15, self.chunk_size)
        
        i = 0
        while i < len(data):
            entry_size = struct.unpack('<I', data[i:i+4])[0]
            i += 4
            entry_data = data[i:i+entry_size]
            message = plog_pb2.LogEntry()
            message.ParseFromString(entry_data)
            self.entries[chunk_num].append(message)
            i += entry_size
    
    def read_entry(self):
        # Read entry at cur_index in cur_chunk
        
        if self.cur_index == -1:
            if self.cur_chunk == 0:
                return None
            
            self.cur_chunk -= 1
            print "cur chunk", self.cur_chunk
            print "cur_index", self.cur_index
            if self.cur_chunk not in self.entries: 
                self.unmarshall_chunk(self.cur_chunk)
                self.cur_index = len(self.entries[self.cur_chunk])-1 # last index in entries dict  
                
        returnEntry = self.entries[self.cur_chunk][self.cur_index]
        self.cur_index -= 1
        return returnEntry
    
    def seek(self, num):
        if num == -1:
            self.cur_index = -1
            self.cur_chunk = len(self.chunks)-1

class FunctionCode(IntEnum):
    FUNC_CODE_DECLAREBLOCKS    =  1, 
    FUNC_CODE_INST_BINOP       =  2, 
    FUNC_CODE_INST_CAST        =  3, 
    FUNC_CODE_INST_GEP         =  4, 
    FUNC_CODE_INST_SELECT      =  5, 
    FUNC_CODE_INST_EXTRACTELT  =  6, 
    FUNC_CODE_INST_INSERTELT   =  7, 
    FUNC_CODE_INST_SHUFFLEVEC  =  8, 
    FUNC_CODE_INST_CMP         =  9, 

    FUNC_CODE_INST_RET         = 10, 
    FUNC_CODE_INST_BR          = 11, 
    FUNC_CODE_INST_SWITCH      = 12, 
    FUNC_CODE_INST_INVOKE      = 13, 
    
    FUNC_CODE_INST_UNREACHABLE = 15, 

    FUNC_CODE_INST_PHI         = 16, 
    FUNC_CODE_INST_ALLOCA      = 19, 
    FUNC_CODE_INST_LOAD        = 20, 
    FUNC_CODE_INST_VAARG       = 23, 
    FUNC_CODE_INST_STORE       = 24, 
    
    FUNC_CODE_INST_EXTRACTVAL  = 26, 
    FUNC_CODE_INST_INSERTVAL   = 27, 
    FUNC_CODE_INST_CMP2        = 28, 
    
    FUNC_CODE_INST_VSELECT     = 29, 
    FUNC_CODE_INST_INBOUNDS_GEP= 30, 
    FUNC_CODE_INST_INDIRECTBR  = 31, 
    
    FUNC_CODE_DEBUG_LOC_AGAIN  = 33, 

    FUNC_CODE_INST_CALL        = 34, 

    FUNC_CODE_DEBUG_LOC        = 35, 
    FUNC_CODE_INST_FENCE       = 36, 
    FUNC_CODE_INST_CMPXCHG     = 37, 
         
    FUNC_CODE_INST_ATOMICRMW   = 38, 
    FUNC_CODE_INST_RESUME      = 39, 
    FUNC_CODE_INST_LANDINGPAD  = 40, 
    FUNC_CODE_INST_LOADATOMIC  = 41, 
         
    FUNC_CODE_INST_STOREATOMIC = 42,  
    BB = 43,
    LLVM_FN = 44,
    LLVM_EXCEPTION = 45
