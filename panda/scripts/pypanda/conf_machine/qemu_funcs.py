from cffi import FFI


ffi = FFI()


ffi.cdef(open("./include/devicestate.h").read())

libpanda = ffi.dlopen("/home/alom/git/panda/build/x86_64-softmmu/libpanda-x86_64.so")
libc = ffi.dlopen(None)

#hwaddr is uint64_t and represents a physical address

#args: const char *name, hwaddr addr, *args maybe **kargs
#return: DeviceState


"""
def sysbus_create_varargs(name, addr, *args):
#	assert (type(name) == type(b'') and type(addr) == type(ffi.new("uint64_t*",1)))

	#import pdb; pdb.set_trace()
	n = ffi.new("char*", name)
	a = ffi.new("int*", addr)

	obj_dict[name] = n
	obj_dict[str(addr)] = a

	return libpanda.sysbus_create_varargs(name,addr)
"""
