from cffi import FFI


ffi = FFI()

#ffi.cdef(open("./hwaddr-preprocessed.h").read())
#ffi.cdef(open("./irq-preprocessed.h").read())
#ffi.cdef(open("./libc-preprocessed.h").read())
#ffi.cdef(open("./qdev-core-preprocessed.h").read())
#ffi.cdef(open("./qdev-preprocessed.h").read())
ffi.cdef(open("./sysbus-preprocessed.h").read())

libpanda = ffi.dlopen("/home/alom/git/panda/build/x86_64-softmmu/libpanda-x86_64.so")
