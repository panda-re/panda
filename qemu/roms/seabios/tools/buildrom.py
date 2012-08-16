#!/usr/bin/env python
# Fill in checksum/size of an option rom, and pad it to proper length.
#
# Copyright (C) 2009  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU GPLv3 license.

import sys

def alignpos(pos, alignbytes):
    mask = alignbytes - 1
    return (pos + mask) & ~mask

def checksum(data):
    ords = map(ord, data)
    return sum(ords)

def main():
    inname = sys.argv[1]
    outname = sys.argv[2]

    # Read data in
    f = open(inname, 'rb')
    data = f.read()
    count = len(data)

    # Pad to a 512 byte boundary
    data += "\0" * (alignpos(count, 512) - count)
    count = len(data)

    # Fill in size field; clear checksum field
    data = data[:2] + chr(count/512) + data[3:6] + "\0" + data[7:]

    # Checksum rom
    newsum = (256 - checksum(data)) & 0xff
    data = data[:6] + chr(newsum) + data[7:]

    # Write new rom
    f = open(outname, 'wb')
    f.write(data)

if __name__ == '__main__':
    main()
