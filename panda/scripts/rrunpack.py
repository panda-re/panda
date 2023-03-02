#!/usr/bin/env python3

import sys, os
import subprocess
import struct
import hashlib

RRPACK_MAGIC = b"PANDA_RR"

# PANDA Packed RR file format (all integers are little-endian):
# 0x00: magic "PANDA_RR"
# 0x08: uint64_t num_instructions
# 0x10: MD5 (16 bytes) of remaining data
# 0x20: archive data in .tar.xz format

if len(sys.argv) != 2:
    print("usage: %s <filename.rr>" % sys.argv[0], file=sys.stderr)
    sys.exit(1)

infname = sys.argv[1]

# Get file info
try:
    with open(infname, 'rb') as f:
        magic, num_guest_insns, file_digest = struct.unpack("<8sQ16s", f.read(0x20))
        if magic != RRPACK_MAGIC:
            print(infname, "is not in PANDA Record/Replay format", file=sys.stderr)
            sys.exit(1)
        print("Verifying checksum...", end=' ')
        m = hashlib.md5()
        while True:
            data = f.read(4096)
            if not data: break
            m.update(data)
        digest = m.digest()
        if digest != file_digest:
            print("FAILED. Aborting.")
            sys.exit(1)
        else:
            print("Success.")
        f.seek(0x20)
        print("Unacking RR log %s with %d instructions..." % (infname, num_guest_insns), end=' ')
        subprocess.check_call(['tar', 'xJvf', '-'], stdin=f)
        print("Done.")
except EnvironmentError:
    print("Failed to open", infname, file=sys.stderr)
    sys.exit(1)
