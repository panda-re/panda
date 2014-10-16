
import subprocess
import struct
import sys


pfx = sys.argv[1]

print "pfx = %s" % pfx


f = open(pfx + ".cr3", "r")
data = f.read(4)


l = struct.unpack("I", data)[0]

print "%d cr3s\n" % l

for i in range(l):
    data = f.read(8)
    cr3 = struct.unpack("Q", data)[0]
    fn = pfx + "-%d" % cr3
    print fn
    subprocess.call( ("/home/tleek/git/panda/qemu/panda_plugins/bir/bp " + fn + " 100000").split() )

