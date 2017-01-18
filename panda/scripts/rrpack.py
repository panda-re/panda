#!/usr/bin/env python2.7

import sys, os
import subprocess
import struct
import hashlib

RRPACK_MAGIC = "PANDA_RR"

# PANDA Packed RR file format (all integers are little-endian):
# 0x00: magic "PANDA_RR"
# 0x08: uint64_t num_instructions
# 0x10: MD5 (16 bytes) of remaining data
# 0x20: archive data in .tar.xz format

if len(sys.argv) != 2:
    print >>sys.stderr, "usage: %s <rr_basename>" % sys.argv[0]
    sys.exit(1)

base = sys.argv[1]
outfname = base + '.rr'

if os.path.exists(outfname):
    print >>sys.stderr, "%s already exists; will not overwrite. Aborting." % outfname
    sys.exit(1)

# Get number of instructions
try:
    with open(base + '-rr-nondet.log', 'rb') as f:
        # num_guest_insns is 64-bit int at offset 16
        f.seek(16)
        num_guest_insns = struct.unpack("<Q", f.read(8))[0]
except EnvironmentError:
    print >>sys.stderr, "Failed to open", base + '-rr-nondet.log. Aborting.'
    sys.exit(1)

print "Packing RR log %s with %d instructions..." % (base, num_guest_insns)
outf = open(outfname, 'wb')
outf.write(RRPACK_MAGIC)
outf.write(struct.pack("<Q", num_guest_insns))
outf.write("\0" * 16) # Placeholder for checksum
outf.flush()
subprocess.check_call(['tar', 'cJf', '-', base + '-rr-snp', base + '-rr-nondet.log'], stdout=outf)
outf.close()

print "Calculating checksum...",
outf = open(outfname, 'r+b')
outf.seek(0x20)
m = hashlib.md5()
while True:
    data = outf.read(4096)
    if not data: break
    m.update(data)
digest = m.digest()
outf.seek(0x10)
outf.write(digest)
outf.close()
print "Done."
