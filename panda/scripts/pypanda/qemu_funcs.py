from cffi import FFI


ffi = FFI()
ffi.cdef("typedef uint32_t target_ulong;")
ffi.cdef(open("include/pthreadtypes.h").read())
ffi.cdef(open("include/panda_x86_support.h").read())
ffi.cdef(open("include/panda_qemu_support.h").read())
ffi.cdef(open("include/panda_datatypes.h").read())

libpanda = ffi.dlopen("/home/alom/git/panda/build/x86_64-softmmu/libpanda-x86_64.so")
libc = ffi.dlopen(None)

#hwaddr is uint64_t and represents a physical address

#args: const char *name, hwaddr addr, *args maybe **kargs
#return: DeviceState


