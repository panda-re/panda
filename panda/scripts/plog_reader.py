#!/usr/bin/python2.7

import sys
import os
import zlib
import struct
from google.protobuf.json_format import MessageToJson
from os.path import dirname, join, realpath

panda_dir = dirname(dirname(dirname(realpath(__file__))))

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

def plogiter(fn):
    #f = open(sys.argv[1])
    f = open(fn)

    version, _, dir_pos, _, chunk_size = struct.unpack('<IIQII', f.read(24))
    #print version, dir_pos, chunk_size

    f.seek(dir_pos)
    num_chunks = struct.unpack('<I', f.read(4))[0]
    #print num_chunks

    if num_chunks == 0:
        sys.exit(0)

    entries = []
    for i in range(num_chunks):
        buf = f.read(24)
        entries.append(struct.unpack('<QQQ', buf))

    if entries[-1][1] != dir_pos:
        entries.append((0, dir_pos, 0))

    #print entries

#    print "["
    for entry, next_entry in zip(entries, entries[1:]):
        start_instr, start_pos, num_entries = entry
        next_pos = next_entry[1]
        f.seek(start_pos)
        zsize = next_pos - start_pos
        #print start_pos, next_pos, zsize,
        zdata = f.read(zsize)
        data = zlib.decompress(zdata, 15, chunk_size)
        #print len(data)
        i = 0
        while i < len(data):
            yieldstr = ""
#            if i != 0: print ","
            if i != 0: yieldstr += ","
            entry_size = struct.unpack('<I', data[i:i+4])[0]
            i += 4
            entry_data = data[i:i+entry_size]
            message = plog_pb2.LogEntry()
            message.ParseFromString(entry_data)
            yield message
#            yield (yieldstr + str(MessageToJson(message)))
#            print MessageToJson(message)
#            print MessageToJson(message)
            i += entry_size
#    print "]"


if __name__ == "__main__":
    print "["
    i=0 
    for plog_entry in plogiter(sys.argv[1]):
        if i!=0:
            print ","
        print MessageToJson(plog_entry)
        i += 1
    print "]"
