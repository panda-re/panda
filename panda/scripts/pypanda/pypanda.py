import sys

if sys.version_info[0] != 3:
	print("Please run with Python 3!")
	sys.exit(0)

from os.path import join as pjoin
from os.path import realpath
import os
from enum import Enum
from colorama import Fore, Style
from panda_datatypes import *
from random import randint
import pdb

debug = True

def progress(msg):
	print(Fore.GREEN + '[pypanda.py] ' + Fore.RESET + Style.BRIGHT + msg +Style.RESET_ALL)


# location of panda build dir
panda_build = realpath(pjoin(os.path.abspath(__file__), "../../../../build"))
home = os.getenv("HOME")


class Panda:

	"""
	arch should be "i386" or "x86_64" or ...
	NB: wheezy is debian:3.2.0-4-686-pae
	"""
	def __init__(self, arch="i386", mem="128M", os_version="debian:3.2.0-4-686-pae", qcow="default", extra_args = "", the_os="linux"):
		self.arch = arch
		self.mem = mem
		self.os = os_version
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

		self.callback = pcb
		self.bindir = pjoin(panda_build, "%s-softmmu" % arch)
		self.panda = pjoin(self.bindir, "qemu-system-%s" % arch)
		self.libpanda = ffi.dlopen(pjoin(self.bindir, "libpanda-%s.so" % arch))
		
		biospath = realpath(pjoin(self.panda,"..", "..",  "pc-bios"))
		bits = None
		if self.arch == "i386":
			bits = 32
		elif self.arch == "x86_64":
			bits = 64
		elif self.arch == "arm":
			bits = 32
		elif self.arch == "aarch64":
			bit = 64
		else:
			print("For arch %s: I need logic to figure out num bits")
		assert (not (bits == None))

		# set os string in line with osi plugin requirements e.g. "linux[-_]64[-_].+"
		self.os_string = "%s-%d-%s" % (the_os,bits,os_version)

		# note: weird that we need panda as 1st arg to lib fn to init?
		self.panda_args = [self.panda, "-m", self.mem, "-display", "none", "-L", biospath, "-os", self.os_string, self.qcow]
		if extra_args:
			self.panda_args.extend(extra_args.split())
		self.panda_args_ffi = [ffi.new("char[]", bytes(str(i),"utf-8")) for i in self.panda_args]
		cargs = ffi.new("char **")
		# start up panda!
		nulls = ffi.new("char[]", b"")
		self.cenvp =  ffi.new("char **",nulls)
		self.len_cargs = ffi.cast("int", len(self.panda_args))
		self.init_run = False
		self.pcb_list = {}

	def init(self):
		if debug:
			progress ("Initializing")
		self.init_run = True
		print("Panda args: [" + (" ".join(self.panda_args)) + "]")
		self.libpanda.panda_init(self.len_cargs, self.panda_args_ffi, self.cenvp)

	def run(self):
		if debug:
			progress ("Running")
		if not self.init_run:
			self.init()
		self.libpanda.panda_run()

	def stop(self):
		if debug:
		    progress ("Stopping guest")
		if self.init_run:
		    self.libpanda.panda_stop()
		else:
		    raise RuntimeError("Guest not running- can't be stopped")

	def begin_replay(self, replaypfx):
		if debug:
			progress ("Replaying %s" % replaypfx)
		charptr = ffi.new("char[]",bytes(replaypfx,"utf-8"))
		self.libpanda.panda_replay(charptr)

	def load_plugin(self, name, args=[]): # TODO: this doesn't work yet
		if debug:
			progress ("Loading plugin %s" % name),
			print("plugin args: [" + (" ".join(args)) + "]")
		n = len(args)
		cargs = []
		assert(len(args)==0), "TODO: support arguments"

		# First set qemu_path so plugins can load (may be unnecessary after the first time)
		panda_name_ffi = ffi.new("char[]", bytes(self.panda,"utf-8"))
		self.libpanda.panda_set_qemu_path(panda_name_ffi)

		name_ffi = ffi.new("char[]", bytes(name,"utf-8"))
		self.libpanda.panda_init_plugin(name_ffi, cargs, n)

	def load_python_plugin(self, init_function, name):
		#pdb.set_trace()
		ffi.cdef("""
		extern "Python" bool init(void*);
		""")
		init_ffi = init_function
		name_ffi = ffi.new("char[]", bytes(name, "utf-8"))
		filename_ffi = ffi.new("char[]", bytes(name, "utf-8"))
		uid_ffi = ffi.cast("void*",randint(0,0xffffffff))
		self.libpanda.panda_load_external_plugin(filename_ffi, name_ffi, uid_ffi, init_ffi)

	def register_callback(self, handle, callback, function):
		cb = callback_dictionary[callback]
		pcb = ffi.new("panda_cb *", {cb.name:function})
		self.libpanda.panda_register_callback_helper(handle, cb.number, pcb)
		self.pcb_list[callback] = (function,pcb, handle)
		if "block" in cb.name:
			self.disable_tb_chaining()

		if debug:
			progress("registered callback for type: %s" % cb.name)

	def enable_callback(self, callback):
		if self.pcb_list[callback]:
			function,pcb,handle = self.pcb_list[callback]
			cb = callback_dictionary[callback]
			progress("enabled callback %s" % cb.name)
			self.libpanda.panda_enable_callback_helper(handle, cb.number, pcb)
			if "block" in cb.name:
				self.disable_tb_chaining()
		else:
			progress("ERROR: plugin not registered");

	def disable_callback(self,  callback):
		if self.pcb_list[callback]:
			function,pcb,handle = self.pcb_list[callback]
			cb = callback_dictionary[callback]
			progress("disabled callback %s" % cb.name)
			self.libpanda.panda_disable_callback_helper(handle, cb.number, pcb)
			if "block" in cb.name:
				self.enable_tb_chaining()
		else:
			progress("ERROR: plugin not registered");


	def unload_plugin(self, name):
		if debug:
			progress ("Unloading plugin %s" % name),
		name_ffi = ffi.new("char[]", bytes(name,"utf-8"))
		self.libpanda.panda_unload_plugin_by_name(name_ffi)

	def unload_plugins(self):
		if debug:
			progress ("Unloading all panda plugins")
		self.libpanda.panda_unload_plugins()

	def rr_get_guest_instr_count(self):
		return self.libpanda.rr_get_guest_instr_count_external()

	def require(self, plugin):
		if not self.init_run:
			self.init()
		charptr = pyp.new("char[]", bytes(plugin,"utf-8"))
		self.libpanda.panda_require(charptr)

	def enable_plugin(self, handle):
		self.libpanda.panda_enable_plugin(handle)

	def disable_plugin(self, handle):
		self.libpanda.panda_disable_plugin(handle)

	def enable_memcb(self):
		self.libpanda.panda_enable_memcb()

	def disable_memcb(self):
		self.libpanda.panda_disable_memcb()

	def enable_llvm(self):
		self.libpanda.panda_enable_llvm()

	def disable_llvm(self):
		self.libpanda.panda_disable_llvm()

	def enable_llvm_helpers(self):
		self.libpanda.panda_enable_llvm_helpers()

	def disable_llvm_helpers(self):
		self.libpanda.panda_disable_llvm_helpers()

	def enable_tb_chaining(self):
		self.libpanda.panda_enable_tb_chaining()

	def disable_tb_chaining(self):
		self.libpanda.panda_disable_tb_chaining()

	def flush_tb(self):
		return self.libpanda.panda_flush_tb()

	def enable_precise_pc(self):
		self.libpanda.panda_enable_precise_pc()

	def disable_precise_pc(self):
		self.libpanda.panda_disable_precise_pc()

	def memsavep(self, file_out):
		newfd = os.dup(f_out.fileno())
		self.libpanda.panda_memsavep(newfd)
		self.libpanda.fclose(newfd)

	def in_kernel(self, cpustate):
		return self.libpanda.panda_in_kernel_external(cpustate)

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


	#string, int, qemu_irq, null
	def sysbus_create_varargs(self, name, addr):
		cname = ffi.new("char[]", bytes(name,"UTF-8"))
		return self.libpanda.sysbus_create_varargs(cname,addr,ffi.NULL)

	def cpu_class_by_name(self, name, cpu_model):
		n = ffi.new("char[]", bytes(name,"UTF-8"))
		c = ffi.new("char[]", bytes(cpu_model,"UTF-8"))
		return self.libpanda.cpu_class_by_name(n, c)

	def object_class_by_name(self, name):
		n = ffi.new("char[]", bytes(name,"UTF-8"))
		return self.libpanda.object_class_by_name(n)

	def object_property_set_bool(self, obj, value, name):
		n = ffi.new("char[]", bytes(name,"UTF-8"))
		e = ffi.new("Error **error_abort")
		return self.libpanda.object_property_set_bool(obj,value,n,e)

	def object_class_get_name(self, objclass):
		return self.libpanda.object_class_get_name(objclass)

	def object_new(self, name):
		if type(name) == type(''):
			n = ffi.new("char[]", bytes(name, "UTF-8"))
		else:
			n = name
		return self.libpanda.object_new(n)

	def object_property_get_bool(self, obj, name):
		n = ffi.new("char[]", bytes(name,"UTF-8"))
		e = ffi.new("Error **error_abort")
		return self.libpanda.object_property_get_bool(obj,n,e)

	def object_property_set_int(self,obj, value, name):
		n = ffi.new("char[]", bytes(name,"UTF-8"))
		e = ffi.new("Error **error_abort")
		return self.libpanda.object_property_set_int(obj, value, n, e)

	def object_property_get_int(self, obj, name):
		n = ffi.new("char[]", bytes(name,"UTF-8"))
		e = ffi.new("Error **error_abort")
		return self.libpanda.object_property_get_int(obj, n, e)

	def object_property_set_link(self, obj, val, name):
		n = ffi.new("char[]", bytes(name,"UTF-8"))
		e = ffi.new("Error **error_abort")
		return self.libpanda.object_property_set_link(obj,val,n,e)

	def object_property_get_link(self, obj, name):
		n = ffi.new("char[]", bytes(name,"UTF-8"))
		e = ffi.new("Error **error_abort")
		return self.libpanda.object_property_get_link(obj,n,e)

	def object_property_find(self, obj, name):
		n = ffi.new("char[]", bytes(name,"UTF-8"))
		return self.libpanda.object_property_find(obj,n,ffi.NULL)

	def memory_region_allocate_system_memory(self, mr, obj, name, ram_size):
		n = ffi.new("char[]", bytes(name,"UTF-8"))
		return self.libpanda.memory_region_allocate_system_memory(mr, obj, n, ram_size)

	def memory_region_add_subregion(self, mr, offset, sr):
		return self.libpanda.memory_region_add_subregion(mr,offset,sr)


	def get_system_memory(self):
		return self.libpanda.get_system_memory()

	def current_sp(self, cpustate):
		return self.libpanda.panda_current_sp_external(cpustate)

	def current_pc(self, cpustate):
		return self.libpanda.panda_current_pc(cpustate)

	def current_asid(self, cpustate):
		return self.libpanda.panda_current_asid(cpustate)

	def disas(self, fout, code, size):
		newfd = os.dup(fout.fileno())
		return self.libpanda.panda_disas(newfd, code, size)

	def set_os_name(self, os_name):
		os_name_new = ffi.new("char[]", bytes(os_name, "utf-8"))
		self.libpanda.panda_set_os_name(os_name_new)

	def cleanup(self):
		self.libpanda.panda_cleanup()

	def virtual_memory_read(self, env, addr, buf, length):
		return self.libpanda.panda_virtual_memory_read_external(env, addr, buf, length)

	def virtual_memory_write(self, env, addr, buf, length):
		return self.libpanda.panda_virtual_memory_write_external(env, addr, buf, length)

	def send_monitor_cmd(self, cmd, do_async=False):
		if debug:
			progress ("Sending monitor command %s" % cmd),

		buf = ffi.new("char[]", bytes(cmd,"UTF-8"))
		n = len(cmd)

		if do_async:
		    self.libpanda.panda_monitor_run_async(buf)
		    return None
		else:
		    ret = self.libpanda.panda_monitor_run(buf)
		    return ffi.string(ret).decode("utf-8", "ignore");

	def load_osi(self):
		self.libpanda_osi = ffi.dlopen(pjoin(self.bindir, "panda/plugins/panda_osi.so"))
		self.libpanda_osi_linux = ffi.dlopen(pjoin(self.bindir, "panda/plugins/panda_osi_linux.so"))
		self.libpanda_osi_test = ffi.dlopen(pjoin(self.bindir, "panda/plugins/panda_osi_test.so"))
	
	def get_current_process(self, cpustate):
		return self.libpanda_osi.get_current_process(cpustate)

	def get_processes(self, cpustate):
		return self.libpanda_osi.get_processes(cpustate)
	
	def get_libraries(self, cpustate, current):
		return self.libpanda_osi.get_libraries(cpustate,current)
	
	def get_modules(self, cpustate):
		return self.libpanda_osi.get_modules(cpustate)
	
	def get_current_thread(self, cpustate):
		return self.libpanda_osi.get_current_thread(cpustate)
	
	def ppp_reg_cb(self):
		pass
