#!/usr/bin/python2.7

import sys
import os
import zlib
import struct
import itertools
from google.protobuf.json_format import MessageToJson
from os.path import dirname

panda_dir = dirname(dirname(dirname(os.path.realpath(__file__))))

# components of paths to be serched
top_dirs = [panda_dir, dirname(panda_dir)]
build_dirs = ['build-panda', 'build', 'opt-panda', 'debug-panda']
arch_dirs = ['i386-softmmu', 'x86_64-softmmu']
searched_paths = []

for dc in itertools.product(top_dirs, build_dirs, arch_dirs):
    d = os.path.join(*dc)
    searched_paths.append(d)
    if not os.path.isdir(d): continue
    try:
        sys.path.append(d)
        import plog_pb2
        break
    except ImportError:
        sys.path.pop()

assert 'plog_pbd2' in sys.modules, "Couldn't load module plog_pb2. Searched paths:\n\t%s" % "\n\t".join(searched_paths)

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
