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




