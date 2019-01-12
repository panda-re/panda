from pypanda import *
from time import sleep
from string import printable
import unicodedata

@panda.callback.init
def init(handle):
	progress("init in python. handle="+str(handle))
	panda.enable_memcb()
	panda.register_callback(handle, panda.virt_mem_after_write, virt_mem_after_write)
	return True


@panda.callback.virt_mem_after_write
def virt_mem_after_write(cpustate,pc, addr, size, buf):
#	pdb.set_trace()
	z = ffi.cast("char*", buf)
	str_build = ""
	for i in range(size):
#		pdb.set_trace()
		value = str(z[i].decode('utf-8','ignore'))
		if value in printable and value != " ":
			str_build += value
	if len(str_build) >= 5:
		progress("cool string: "+str(str_build))
#	panda.virtual_memory_read(cpustate, addr, store_buf, size)
	return 0

panda = Panda(qcow=None, ,extra_args='--hda /home/luke/buildroot/buildroot/output/images/rootfs.ext2 --kernel /home/luke/buildroot/buildroot/output/images/bzImage --nographic --append \"console=tty1 root=/dev/sda\"')
panda.load_python_plugin(init,"Cool Plugin")
panda.run()
