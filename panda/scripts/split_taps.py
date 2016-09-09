#!/usr/bin/env python

import gzip
import time

def main(logfile, prefix, num_callers=1):
    if logfile.endswith('.gz'):
        f = gzip.GzipFile(logfile)
    else:
        f = open(logfile)

    filemap = {}

    for line in f:
        # Avoid "too many open files" -- flush the file descriptor map
        if len(filemap) > 1000:
            for o in filemap.values(): o.close()
            filemap = {}

        callers, pc, cr3, addr, n, val = line.strip().rsplit(" ", 5)
        callers = callers.split()
        fname = prefix + "." + ".".join( callers[-num_callers:] + [pc, cr3] ) + ".dat"
        if fname not in filemap:
            filemap[fname] = open(fname,'a')

        val = val.decode('hex')
        filemap[fname].write(val)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Split a logfile containing tap point data into its constitutent taps.')
    parser.add_argument('logfile', help='log file containing tap point data (can be gzipped)')
    parser.add_argument('prefix', help='prefix for output files')
    parser.add_argument('-c', '--callers', type=int, default=1,
            help='levels of calling context to use when splitting')
    args = parser.parse_args()
    main(args.logfile, args.prefix, num_callers=args.callers)
