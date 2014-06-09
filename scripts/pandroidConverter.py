#!/usr/bin/env python

import os
import shutil
import ConfigParser
import subprocess
import sys

def expandWithZeroes(filename, fullsize):
    if type(fullsize) == type(''):
        if fullsize.isdigit():
            fullsize = int(fullsize)
        elif fullsize.endswith('m'):
            fullsize = int(fullsize[:-1]) * 1024 * 1024
        elif fullsize.endswith('k'):
            fullsize = int(fullsize[:-1]) * 1024
        elif fullsize.endswith('g'):
            fullsize = int(fullsize[:-1]) * 1024 * 1024 * 1024
        else:
            raise Exception("invalid partition size %s" % fullsize)
    # get current size
    filledsize = os.stat(filename).st_size
    morelen = fullsize - filledsize
    print "File: %s" % filename
    print "Virtual size:  %d" % fullsize
    print "Physical size: %d" % filledsize
    print "Expand by:     %d" % morelen
    with open(filename, 'ab') as image:
        image.write('\xff' * morelen)
    print "Expansion complete"

def makeQCow(filename):
    print "Converting %s to QCOW2" % filename
    subprocess.call(['qemu-img', 'convert', '-f', 'raw', '-O', 'qcow2', filename, filename+'.qcow2'])
            
def convertFile(current, target, newsize):
    shutil.copyfile(current, target)
    expandWithZeroes(target, newsize)
    makeQCow(target)

FAKE_SECTION = 'main'
class FakeSecHead(object):
    """ From 
    http://stackoverflow.com/questions/2819696/parsing-properties-file-in-python/2819788#2819788
    Use ConfigParser on .ini files without any sections
    """
    def __init__(self, fp):
        self.fp = fp
        self.sechead = '['+FAKE_SECTION+']\n'
    def readline(self):
        if self.sechead:
            try: return self.sechead
            finally: self.sechead = None
        else: return self.fp.readline()

def translateImage(avdname):
    print "NOTE: These are NAND images, empty space is 0xFF instead of 0x00, so they aren't sparse"
    iniPath = os.path.join(os.getenv('HOME'), '.android/avd', avdname + '.avd', 'hardware-qemu.ini')
    config = ConfigParser.ConfigParser()
    config.readfp(FakeSecHead(open(iniPath)))
    
    systemsize = config.get(FAKE_SECTION, 'disk.systempartition.size')
    systempath = config.get(FAKE_SECTION, 'disk.systempartition.initpath')
    convertFile(systempath, "system-pandroid", systemsize)
    
    cachepath = config.get(FAKE_SECTION, 'disk.cachepartition.path')
    cachesize = config.get(FAKE_SECTION, 'disk.cachepartition.size')
    convertFile(cachepath, "cache-pandroid", cachesize)
    
    datasize = config.get(FAKE_SECTION, 'disk.datapartition.size')
    datapath = config.get(FAKE_SECTION, 'disk.datapartition.path')
    convertFile(datapath, "data-pandroid", datasize)
    
    kernelpath = config.get(FAKE_SECTION, "kernel.path")
    shutil.copyfile(kernelpath, "kernel")
    initramfs  = config.get(FAKE_SECTION, "disk.ramdisk.path")
    shutil.copyfile(initramfs, "initramfs")

def usage():
    print sys.argv[0] + " AVD-name"
    print "Convert disk images used by an Android Virtual Devices into QCOW2 files."
    print "Results: system-pandroid.qcow2, cache-pandroid.qcow2, data-pandroid.qcow2, kernel, initramfs"
    print "Since these are NAND images, empty space is 0xFF instead of 0x00, so they aren't sparse"
    
if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    else:
        translateImage(sys.argv[1])
