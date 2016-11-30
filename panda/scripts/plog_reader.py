import sys
import zlib
import plog_pb2
import struct
from google.protobuf.json_format import MessageToJson

f = open(sys.argv[1])

version, _, dir_pos, _, chunk_size = struct.unpack('<IIQII', f.read(24))

f.seek(dir_pos)
num_chunks = struct.unpack('<I', f.read(4))[0]
#print num_chunks

entries = []
for i in range(num_chunks):
    buf = f.read(24)
    entries.append(struct.unpack('<QQQ', buf))

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
        entry_size = struct.unpack('<I', data[i:i+4])[0]
        i += 4
        entry_data = data[i:i+entry_size]
        message = plog_pb2.LogEntry()
        message.ParseFromString(entry_data)
        print MessageToJson(message)
        i += entry_size
