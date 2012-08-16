#!/usr/bin/env python
# Script to check a bios image and report info on it.
#
# Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU GPLv3 license.

import sys
import layoutrom

def main():
    # Get args
    objinfo, rawfile, outfile = sys.argv[1:]

    # Read in symbols
    objinfofile = open(objinfo, 'rb')
    symbols = layoutrom.parseObjDump(objinfofile, 'in')[1]

    # Read in raw file
    f = open(rawfile, 'rb')
    rawdata = f.read()
    f.close()
    datasize = len(rawdata)
    finalsize = 64*1024
    if datasize > 64*1024:
        finalsize = 128*1024
        if datasize > 128*1024:
            finalsize = 256*1024

    # Sanity checks
    start = symbols['code32flat_start'].offset
    end = symbols['code32flat_end'].offset
    expend = layoutrom.BUILD_BIOS_ADDR + layoutrom.BUILD_BIOS_SIZE
    if end != expend:
        print "Error!  Code does not end at 0x%x (got 0x%x)" % (
            expend, end)
        sys.exit(1)
    if datasize > finalsize:
        print "Error!  Code is too big (0x%x vs 0x%x)" % (
            datasize, finalsize)
        sys.exit(1)
    expdatasize = end - start
    if datasize != expdatasize:
        print "Error!  Unknown extra data (0x%x vs 0x%x)" % (
            datasize, expdatasize)
        sys.exit(1)

    # Print statistics
    runtimesize = datasize
    if '_reloc_abs_start' in symbols:
        runtimesize = end - symbols['code32init_end'].offset
    print "Total size: %d  Fixed: %d  Free: %d (used %.1f%% of %dKiB rom)" % (
        datasize, runtimesize, finalsize - datasize
        , (datasize / float(finalsize)) * 100.0
        , finalsize / 1024)

    # Write final file
    f = open(outfile, 'wb')
    f.write(("\0" * (finalsize - datasize)) + rawdata)
    f.close()

if __name__ == '__main__':
    main()
