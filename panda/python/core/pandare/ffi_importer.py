"""
This internal module is a workaround to maintain state of cffi objects between submodules.
It simply imports cffi and give you a handle to the `ffi` variable.
"""

# necessary to not recreate ffi, but help along mixins
from cffi import FFI

ffi = FFI()

def set_ffi(ffi_new):
    global ffi
    ffi = ffi_new
