
import sys
from os.path import join as pjoin
from os.path import realpath
import os
from ctypes import *
from enum import Enum
from colorama import Fore, Style
from panda_datatypes import *

debug = True


def progress(msg):
	print(Fore.GREEN + '[pypanda.py] ' + Fore.RESET + Style.BRIGHT + msg + Style.RESET_ALL)


# location of panda build dir
panda_build = realpath(pjoin(os.path.abspath(__file__), "../../../build"))
home = os.getenv("HOME")


def strarr2c(str_arr):
	c_str_arr = (POINTER(c_char) * len(str_arr))()
	for ix,el in enumerate(str_arr):
		c_str_arr[ix] = create_string_buffer(str.encode(el))
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
				print("Missing qcow -- %s" % self.qcow)
				print("Please go create that qcow and give it to moyix!")
		self.bindir = pjoin(panda_build, "%s-softmmu" % arch)
		self.panda = pjoin(self.bindir, "qemu-system-%s" % arch)
		self.libpanda = ffi.dlopen(pjoin(self.bindir, "libpanda-%s.so" % arch))
		biospath = realpath(pjoin(self.panda, "..", "..", "pc-bios"))
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
#		cargs = strarr2c(self.panda_args)
		self.panda_args_ffi = [ffi.new("char[]", bytes(str(i),"utf-8")) for i in self.panda_args]
		cargs = ffi.new("char **")
		
		# start up panda!
		nulls = ffi.new("char[]", b"")
		cenvp =  ffi.new("char **",nulls)
		len_cargs = ffi.cast("int", len(self.panda_args))
		print("Panda args: [" + (" ".join(self.panda_args)) + "]")
		self.libpanda.panda_init(len_cargs, self.panda_args_ffi, cenvp)


	def load_plugin(self, name, args=[]):
		if debug:
			progress ("Loading plugin %s" % name),
			print("plugin args: [" + (" ".join(args)) + "]")
		n = len(args)
		cargs = [] #strarr2c(args)
		self.libpanda.panda_init_plugin(create_string_buffer(name), cargs, n)

	def load_python_plugin(self, plugin):
		# plugin.init
		# load_python_plugin -> lep -> init -> capi_init(pcb) -> init -> lep -> load_python_plugin -> python
		ffi.cdef("""
		extern "Python" bool init(void*);		
		""")
		func = plugin.init
		name = ffi.new("char[]", bytes(plugin.name, "utf-8"))
		filename = ffi.new("char[]", bytes(plugin.filename, "utf-8"))
		uuid = ffi.cast("void*",plugin.uuid)
		
		self.libpanda.panda_load_external_plugin(filename, name, uuid, func)

	def register_callback(self, handle, enum_value, function):
		progress("got to register_callback")
		pcb = ffi.new("panda_cb *", {"before_block_exec":function})
		print(pcb.before_block_exec)
		self.libpanda.panda_register_callback_helper(handle, enum_value, pcb)
		print(pcb.before_block_exec)
		progress(" got to end of register_callback")

	def begin_replay(self, replaypfx):
		if debug:
			progress ("Replaying %s" % replaypfx)
		self.libpanda.panda_replay(create_string_buffer(replaypfx))

	def run(self):
		if debug:
			progress ("Running")
		self.libpanda.panda_run()


class Plugin:
	def __init__(self,name,uuid):
		self.name = name
		self.uuid = uuid
		self.filename = "C:/"+name # extraneous

class CoolPlugin(Plugin):
	def __init__(self):
		super().__init__("CoolPlugin", uuid=43)
	@ffi.callback("bool(void*)")
	def init(handle):	
		progress("init in python. handle="+str(handle))
		# panda_cb pcb = { .before_block_exec = self.before_block_execute };
#		pcb = panda_cb()
#		pcb.before_block_translate = 0x242424242
		panda.register_callback(handle, 3, before_block_execute)
	
@ffi.callback("int(int*, int*)")
def before_block_execute(a,b):
	progress("before block in python")
	return 0

panda = Panda(qcow="/home/luke/ubuntu-14.04-server-cloudimg-i386-disk1.img")

#panda.load_plugin("asidstory")

#panda.begin_replay("/home/recordings/this_is_a_recording")

cool_plugin = CoolPlugin()
panda.load_python_plugin(cool_plugin)
progress("here")
panda.run()
