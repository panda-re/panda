from cffi import FFI


ffi = FFI()


ffi.cdef(open("./include/header.h").read())
ffi.cdef(open("./include/header2.h").read())

libpanda = ffi.dlopen("/home/alom/git/panda/build/x86_64-softmmu/libpanda-x86_64.so")
libc = ffi.dlopen(None)



#hwaddr is uint64_t and represents a physical address

#args: const char *name, hwaddr addr, *args maybe **kargs
#return: DeviceState

obj_dict = {}

def sysbus_create_varargs(name, addr, *args):
#	assert (type(name) == type(b'') and type(addr) == type(ffi.new("uint64_t*",1)))

	#import pdb; pdb.set_trace()
	n = ffi.new("char*", name)
	a = ffi.new("hwaddr*", addr)

	obj_dict[name] = n
	obj_dict[str(addr)] = a

	dev = libpanda.sysbus_create_varargs(name,addr)

	return dev


def cpu_class_by_name(name, cpu_model):
	n = ffi.new("char*", name)
	c = ffi.new("char*", cpu_model)

	obj_dict[name] = n
	obj_dict[cpu_model] = c

	cpu_class = libpanda.cpu_class_by_name(


		

def object_new(name):
	return 0

def object_class_by_name(name):
	return 0

def object_class_get_name(obj_class):
	return 0

def object_property_find(obj, name, error):
	return 0

def object_property_set_bool(obj, value, name, error):
	return 0

def object_property_set_int(obj, value, name, error):
	return 0

def object_property_set_link(obj,value,name,error):
	return 0

def memory_region_allocate_system_memory(mem_reg, obj, name, size):
	return 0

def memory_region_add_subregion(mem_reg, offset, sub_mem_reg):
	return 0



