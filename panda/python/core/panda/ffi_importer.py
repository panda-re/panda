"""
This module is a workaround to maintain state of and not recreate cffi objects between mixins. All it does is import cffi and give you a handle to ffi.
"""

# necessary to not recreate ffi, but help along mixins
from cffi import FFI
ffi = FFI()