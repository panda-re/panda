

import sys
import itertools
import os
import struct
from os.path import dirname

from google.protobuf.json_format import MessageToJson


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

assert 'plog_pb2' in sys.modules, "Couldn't load module plog_pb2. Searched paths:\n\t%s" % "\n\t".join(searched_paths)



with open(sys.argv[1], "rb") as pbf:

    while True:
        try:

            msg_size, = struct.unpack("I", pbf.read(4))
            
            log_entry = plog_pb2.LogEntry()
            log_entry.ParseFromString(pbf.read(msg_size))

            print(MessageToJson(log_entry))
            
        except:
            break
        
