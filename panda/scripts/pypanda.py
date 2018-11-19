
import sys
from os.path import join as pjoin
from os.path import realpath
import os
from ctypes import *
from enum import Enum

# location of panda build dir
panda_build = realpath(pjoin(os.path.abspath(__file__), "../../../build"))
home = os.getenv("HOME")

class PandaState(Enum):
    UNINT = 1
    INIT_DONE = 2
    IN_RECORD = 3
    IN_REPLAY = 4


def strarr2c(str_arr):
    c_str_arr = (POINTER(c_char) * len(str_arr))()
    for ix,el in enumerate(str_arr):
        c_str_arr[ix] = create_string_buffer(el)
    return c_str_arr

class Panda:

    """
    arch should be "i386" or "x86_64" or ...
    NB: wheezy is debian:3.2.0-4-686-pae
    """    
    def __init__(self, arch="i386", mem="128M", the_os="debian:3.2.0-4-686-pae", qcow="default", extra_args = []):
        self.arch = arch
        self.mem = mem
        self.os = the_os
        self.qcow = qcow
        if qcow is None:
            # this means we wont be using a qcow -- replay only presumably
            pass
        else:
            if qcow is "default":
                # this means we'll use arch / mem / os to find a qcow
                self.qcow = pjoin(home, ".panda", "%s-%s-%s.qcow" % (the_os, arch, self.mem))
            if not (os.path.exists(self.qcow)):
                print "Missing qcow -- %s" % self.qcow
                print "Please go create that qcow and give it to moyix!"
        self.bindir = pjoin(panda_build, "%s-softmmu" % arch)
        self.panda = pjoin(self.bindir, "qemu-system-%s" % arch)
        self.libpanda = cdll.LoadLibrary(pjoin(self.bindir, "libpanda-%s.so" % arch))
        biospath = realpath(pjoin(self.panda, "..", "..", "pc-bios"))
        self.panda_args = [self.panda, "-m", self.mem, "-nographic", "-L", biospath]
        cargs = strarr2c(self.panda_args)
        # start up panda!
        # note: weird that we need panda as 1st arg to lib fn to init? 
        cenvp =  POINTER(c_int)()
        self.libpanda.panda_init(len(cargs), cargs, cenvp)


    def load_plugin(self, name, args=[]):
        n = len(args)
        cargs = strarr2c(args)
        self.libpanda.panda_init_plugin(create_string_buffer(name), cargs, n)

    def replay(self, replaypfx):
        pass

    def run(self):
        self.libpanda.panda_run()




panda = Panda()

panda.load_plugin("asidstory")

panda.replay("/home/tleek/tmp/toy/toy")


