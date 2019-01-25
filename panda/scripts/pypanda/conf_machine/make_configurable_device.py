from cffi import FFI


ffi = FFI()


ffi.cdef(open("./include/header.h").read())

#ffi.cdef(open("./include/libc.h").read())
#ffi.cdef(open("./include/ram_addr.h").read())
#ffi.cdef(open("./include/sysbus.h").read())

#ffi.cdef(open("./hwaddr-preprocessed.h").read())
#ffi.cdef(open("./irq-preprocessed.h").read())
#ffi.cdef(open("./qdev-core-preprocessed.h").read())
#ffi.cdef(open("./qdev-preprocessed.h").read())


libpanda = ffi.dlopen("/home/alom/git/panda/build/x86_64-softmmu/libpanda-x86_64.so")
