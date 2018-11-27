
import sys
from os.path import join as pjoin
from os.path import realpath
import os
from ctypes import *
from enum import Enum
from colorama import Fore, Style

debug = True


def progress(msg):
    print Fore.GREEN + '[pypanda.py] ' + Fore.RESET + Style.BRIGHT + msg + Style.RESET_ALL
#    print


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


# NOTE:
# map from the_os input to Panda to os-string needed by panda
# Note that qcow for this os is assumed to exist and live in
# ~/.panda/"%s-%s-%s.qcow" % (the_os, arch, mem)
os2osstring = {
    "debian:3.2.0-4-686-pae" : "linux-32-debian:3.2.0-4-686-pae"
}
    

class Panda:

    """
    arch should be "i386" or "x86_64" or ...
    NB: wheezy is debian:3.2.0-4-686-pae
    """    
    def __init__(self, arch="i386", mem="128M", the_os="debian:3.2.0-4-686-pae", qcow="default", extra_args = []):
        if debug:
            progress("Initializing panda")
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
                self.qcow = pjoin(home, ".panda", "%s-%s-%s.qcow" % (the_os, arch, mem))
            if not (os.path.exists(self.qcow)):
                print "Missing qcow -- %s" % self.qcow
                print "Please go create that qcow and give it to moyix!"
        self.bindir = pjoin(panda_build, "%s-softmmu" % arch)
        self.panda = pjoin(self.bindir, "qemu-system-%s" % arch)
        self.libpanda = CDLL(pjoin(self.bindir, "libpanda-%s.so" % arch), mode=RTLD_GLOBAL)
        biospath = realpath(pjoin(self.panda, "..", "..", "pc-bios"))

        bits = None
        if self.arch == "i386":
            bits = 32
        elif self.arch == "x86_64":
            bits = 64
        else:
            print "For arch %s: I need logic to figure out num bits"
        assert (not (bits == None))            

        # note: weird that we need panda as 1st arg to lib fn to init? 
        self.panda_args = [self.panda, "-m", self.mem, "-display", "none", "-L", biospath, "-os", os2osstring[the_os]]
        cargs = strarr2c(self.panda_args)
        # start up panda!
        cenvp =  POINTER(c_int)()

        print "Panda args: [" + (" ".join(self.panda_args)) + "]"
        self.libpanda.panda_init(len(cargs), cargs, cenvp)


    def load_plugin(self, name, args=[]):
        if debug:
            progress ("Loading plugin %s" % name),
            print "plugin args: [" + (" ".join(args)) + "]"
        n = len(args)
        cargs = strarr2c(args)
        self.libpanda.panda_init_plugin(create_string_buffer(name), cargs, n)

    def begin_replay(self, replaypfx):
        if debug:
            progress ("Replaying %s" % replaypfx)
        self.libpanda.panda_replay(create_string_buffer(replaypfx))

    def run(self):
        if debug:
            progress ("Running")
        self.libpanda.panda_run()




panda = Panda()

panda.load_plugin("asidstory")

panda.begin_replay("/home/tleek/tmp/toy/toy")


