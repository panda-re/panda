from pypanda import *
from time import sleep



panda = Panda(arch="arm",qcow="/home/alom/.panda/arm_wheezy.qcow",extra_args="-M virt")
print ("pypanda: done with pre")

@panda.callback.init
def init(handle):
	panda.register_callback(handle, panda.callback.after_machine_init, after_machine_init)
	return True

@panda.callback.after_machine_init
def after_machine_init(cpustate):
	print("running after_machine_init")
#	print(panda.sysbus_create_varargs("l2x0", 503357440))
	arm_cpu = panda.cpu_class_by_name("arm-cpu", "cortex-a15")
	cpu_name = panda.object_class_get_name(arm_cpu)
	obj = panda.object_new(cpu_name)
	panda.object_property_set_bool(obj, True,"has_el3")
	obj_bool = panda.object_property_get_bool(obj, "has_el3")
	obj_property = panda.object_property_find(obj,"reset-cbar")
	panda.object_property_set_int(obj, 100,"reset-cbar")
	obj_int = panda.object_property_get_int(obj,"reset-cbar")
	sys_mem= panda.get_system_memory()
	obj_2 = ffi.cast("Object*",sys_mem)
	panda.object_property_set_link(obj, obj_2, "memory")
	obj_link = panda.object_property_get_link(obj,"memory")
	mem_reg = ffi.new("MemoryRegion*")
	print("arm_cpu: %s" % str(arm_cpu))
	print("cpu_name: %s" % str(cpu_name))
	print("obj: %s" % str(obj))
	print("obj_bool: %s" % str(obj_bool))
	print("obj_property: %s" % str(obj_property))
	print("obj_int: %s" % str(obj_int))
	print("obj_2: %s" % str(obj_2))
	print("obj_link: %s" % str(obj_link))
	print("mem_reg: %s" % str(mem_reg))
#	panda.memory_region_allocate_system_memory(mem_reg,ffi.NULL,"ram",100)
#	panda.memory_region_add_subregion(sys_mem,100,mem_reg)
	print("after_machine_init done")
        

#panda = Panda(qcow="/home/alom/ubuntu-14.04-server-cloudimg-i386-disk1.img")

panda.load_python_plugin(init,"make_configurable_device")
print ("pypanda: loaded plugin -- running")

panda.init()
print ("pypanda: panda initialized")

panda.run()
