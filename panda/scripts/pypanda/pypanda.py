
import sys
from os.path import join as pjoin
from os.path import realpath
import os
from enum import Enum
from colorama import Fore, Style
from panda_datatypes import *
from random import randint
import pdb

debug = True
pyp = ffi

def progress(msg):
	print(Fore.GREEN + '[pypanda.py] ' + Fore.RESET + Style.BRIGHT + msg + Style.RESET_ALL)


# location of panda build dir
panda_build = realpath(pjoin(os.path.abspath(__file__), "../../../../build"))
home = os.getenv("HOME")


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
		self.static_var = 0
		self.qcow = qcow
		if qcow is None:
			# this means we wont be using a qcow -- replay only presumably
			pass
		else:
			if qcow is "default":
				# this means we'll use arch / mem / os to find a qcow
				self.qcow = pjoin(home, ".panda", "%s-%s-%s.qcow" % (the_os, arch, mem))
			if not (os.path.exists(self.qcow)):
				print("Missing qcow -- %s" % self.qcow)
				print("Please go create that qcow and give it to moyix!")
		self.bindir = pjoin(panda_build, "%s-softmmu" % arch)
		self.panda = pjoin(self.bindir, "qemu-system-%s" % arch)
		self.libpanda = ffi.dlopen(pjoin(self.bindir, "libpanda-%s.so" % arch))
		biospath = realpath(pjoin(self.panda,"..", "..",  "pc-bios"))
		bits = None
		if self.arch == "i386":
			bits = 32
		elif self.arch == "x86_64":
			bits = 64
		else:
			print("For arch %s: I need logic to figure out num bits")
		assert (not (bits == None))
		
		# note: weird that we need panda as 1st arg to lib fn to init?
		self.panda_args = [self.panda, "-m", self.mem, "-display", "none", "-L", biospath, "-os", os2osstring[the_os], self.qcow]
		self.panda_args_ffi = [ffi.new("char[]", bytes(str(i),"utf-8")) for i in self.panda_args]
		cargs = ffi.new("char **")
		# start up panda!
		nulls = ffi.new("char[]", b"")
		cenvp =  ffi.new("char **",nulls)
		len_cargs = ffi.cast("int", len(self.panda_args))
		print("Panda args: [" + (" ".join(self.panda_args)) + "]")
		self.len_cargs = len_cargs
		self.cenvp = cenvp
		self.libpanda.panda_pre(len_cargs, self.panda_args_ffi, cenvp)


	def init(self):
		if debug:
			progress ("Initializing from cmdline")
		self.libpanda.panda_init(self.len_cargs, self.panda_args_ffi, self.cenvp)

	def run(self):
		if debug:
			progress ("Running")
		self.libpanda.panda_run()

	def begin_replay(self, replaypfx):
		if debug:
			progress ("Replaying %s" % replaypfx)
		charptr = ffi.new("char[]",bytes(replaypfx,"utf-8")) 
		self.libpanda.panda_replay(charptr)

	def load_plugin(self, name, args=[]):
		if debug:
			progress ("Loading plugin %s" % name),
			print("plugin args: [" + (" ".join(args)) + "]")
		n = len(args)
		cargs = []
		self.libpanda.panda_init_plugin(create_string_buffer(name), cargs, n)


	def load_python_plugin(self, init_function, name):
#		pdb.set_trace()
		ffi.cdef("""
		extern "Python" bool init(void*);		
		""")
		init_ffi = init_function
		name_ffi = ffi.new("char[]", bytes(name, "utf-8"))
		filename_ffi = ffi.new("char[]", bytes(name, "utf-8"))
		uid_ffi = ffi.cast("void*",randint(0,0xffffffff))
		self.libpanda.panda_load_external_plugin(filename_ffi, name_ffi, uid_ffi, init_ffi)


	def register_callback(self, handle, name, number, function):
		pcb = ffi.new("panda_cb *", {name:function})
		self.libpanda.panda_register_callback_helper(handle, number, pcb)
		if debug:
			progress("registered callback for type: %s" %name)
	
	def require(self, plugin):
		charptr = pyp.new("char[]", bytes(plugin,"utf-8"))
		self.libpanda.panda_require(charptr)
	
	def in_kernel(self, cpustate):
#		pdb.set_trace()
		if self.arch == "i386":
			cpu = cpustate.env_ptr #ffi.cast("CPUX86State*", cpustate.env_ptr)S
			HF_CPL_SHIFT = 0
			HF_CPL_MASK = 3 << HF_CPL_SHIFT
			return (cpu.hflags & HF_CPL_SHIFT) == 0 
		elif self.arch == "arm":
			return env.regs[13]
		elif self.arch == "ppc":
			return env.msr_pr
		else:
			print("in_kernel() not implemented for target architecture.")
		return 0
	
	def current_sp(self, cpustate): # under construction
		if self.arch == "i386":
			if self.in_kernel(cpustate):
				'''			
				probably an enum at some point here.
				#define R_EAX 0
				#define R_ECX 1
				#define R_EDX 2
				#define R_EBX 3
				#define R_ESP 4
				#define R_EBP 5
				#define R_ESI 6
				#define R_EDI 7
				'''
				R_ESP = 4
				return cpustate.env_ptr.regs[R_ESP]
	#		else:
	#			esp0 = 4
	#			tss_base = env.tr.base + esp0
	#			kernel_esp = 0
	#			self.virtual_memory_rw(cpustate, tss_base, 
		return 0
