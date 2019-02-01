from enum import Enum
from ctypes import *

from cffi import FFI
ffi = FFI()
ffi.cdef("typedef uint32_t target_ulong;")
ffi.cdef(open("include/pthreadtypes.h").read())
ffi.cdef(open("include/panda_x86_support.h").read())
ffi.cdef(open("include/panda_qemu_support.h").read())
ffi.cdef(open("include/panda_datatypes.h").read())
ffi.cdef(open("include/header.h").read())

class PandaState(Enum):
	UNINT = 1
	INIT_DONE = 2
	IN_RECORD = 3
	IN_REPLAY = 4

class Callback():
	def __init__(name, number):
		self.name = name
		self.number = number

#class CB_types():
#	before_block_exec = Callback("before_block_exec", 3)
#	before_block_exec_invalidate_opt = Callback("before_block_exec_invalidate_opt", 2)
#	after_block_exec = Callback("after_block_exec", 4)
#	before_block_translate = Callback("before_block_translate", 5)
#	after_block_translate = Callback("after_block_translate", 6)
	
	
