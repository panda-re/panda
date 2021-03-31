#!/usr/bin/env python3
"""
Functionality to interact with the PANDA Log.
"""

import sys
import os
import zlib
import struct
import itertools
from google.protobuf.json_format import MessageToJson
from os.path import dirname, join, isdir
from importlib import import_module
from pandare import plog_pb2

class PLogReader:
    def __init__(self, fn, arch="i386"): 
        self.f = open(fn, "rb")
        self.version, _, self.dir_pos, _, self.chunk_gsize = struct.unpack('<IIQII', self.f.read(24))

        self.f.seek(self.dir_pos)
        self.nchunks, = struct.unpack('<I', self.f.read(4)) # number of chunks
        self.chunks = self.f.read(24*self.nchunks)          # chunks buffer
        self.chunk_idx = 0                                  # index of current chunk
        self.chunk_size = 0                                 # size of current chunk
        self.chunk_data = None                              # data of current chunk
        self.chunk_data_idx = 0

    def __iter__(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.f.close()
        self.f = self.chunk_data = None

    def __next__(self):
        # ran out of chunks
        if not self.chunk_idx < self.nchunks:
            raise StopIteration

        if self.chunk_data is None:
            # unpack ins, pos, nentries for this and the next chunk
            cur = struct.unpack_from('<QQQ', self.chunks, 24*self.chunk_idx)
            if self.chunk_idx + 1 < self.nchunks:
                nxt = struct.unpack_from('<QQQ', self.chunks, 24*(self.chunk_idx+1))
                zchunk_size = nxt[1] - cur[1]
            else:
                # setting the compressed chunk size to -1 will
                # result in reading the remaining of the file
                zchunk_size = -1

            # read and decompress chunk data
            self.f.seek(cur[1])
            self.chunk_data = zlib.decompress(self.f.read(zchunk_size), 15, self.chunk_gsize)
            self.chunk_size = len(self.chunk_data)
            self.chunk_data_idx = 0

        # parse message - we're using a fresh message
        # using MergeFromString() is slightly faster than using ParseFromString()
        msg_size, = struct.unpack_from('<I', self.chunk_data, self.chunk_data_idx)
        msg = plog_pb2.LogEntry()
        msg_start = self.chunk_data_idx + 4
        msg_end = msg_start + msg_size
        msg.MergeFromString(self.chunk_data[msg_start:msg_end])

        # update state
        self.chunk_data_idx = msg_end

        if not self.chunk_data_idx < self.chunk_size:
            self.chunk_idx += 1
            self.chunk_size = 0
            self.chunk_data = None
            self.chunk_data_idx = 0

        return msg

if __name__ == "__main__":
    print('[')
    with PLogReader(sys.argv[1], arch="i386" if len(sys.argv) < 3 else sys.argv[2]) as plr:
        for i, m in enumerate(plr):
            if i > 0: print(',')
            print(MessageToJson(m), end='')
    print('\n]')
