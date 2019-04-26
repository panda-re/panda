from pypanda import *
from time import sleep
import pdb


panda = Panda(arch="arm",qcow="/home/alom/.panda/arm_wheezy.qcow",extra_args="-M rehosting")

print ("pypanda: done with pre")


c_dict = {}

def add_c_string(s):
	if s not in c_dict:
		n = ffi.new("char[]", bytes(s,"UTF-8"))
		c_dict[s] = n
	return c_dict[s]

def add_c_structure(obj, s):
	if s not in c_dict:
		n = ffi.new(obj, s)
		c_dict[s] = n
	return c_dict[s]

@panda.callback.init
def init(handle):
	panda.register_callback(handle, panda.callback.during_machine_init, during_machine_init)
	return True

@panda.callback.during_machine_init
def during_machine_init(machinestate):
	
	#Constants
	#machine_irqs structure
	#variables below: if changing them, change header file as well

	#things i made not static
	#lookup_gic
	#dev_mem_map
	#file_mem_map
	#parse_mem_map
	#irqmap
	#create_internal_gic
	#create_one_flash
	#create_external_gic
	
	#instead of RH_DBG im using python print statements

	#didnt know how to handle ARMCPU(first_cpu)

	NUM_IRQS = 256
	GIC_NR_SGIS = 16
	REHOSTING_MAX_CPUS = 4
	GIC_INTERNAL = 32
	TYPE_ARM_CPU = add_c_string("arm-cpu")
	MAX_MEM_MAPPED_FILES = 10

	print("running during_machine_init")
	
	s_mem = panda.g_malloc0(ffi.sizeof("machine_irqs"))
	s = ffi.cast("machine_irqs*", s_mem)
	c_dict['s'] = s

	sysmem = panda.get_system_memory()

	gic_version = 2
	
	vbi_mem = panda.g_malloc0(ffi.sizeof("RehostingBoardInfo")) 
	vbi = ffi.cast("RehostingBoardInfo*", vbi_mem)
	c_dict['vbi'] = vbi

	ram = ffi.new("MemoryRegion*")
	c_dict['ram_mr'] = ram
	
	firmware_loaded = (panda.libpanda.bios_name != ffi.NULL) or (panda.drive_get(panda.libpanda.IF_PFLASH,0,0) != ffi.NULL)
	
	vbi.cpu_model = machinestate.cpu_model
	
	assert(vbi != ffi.NULL)
	assert(s != ffi.NULL)
	
	if(not vbi.cpu_model):
		cpu_model = add_c_string("cortex-a15")
		vbi.cpu_model = cpu_model
	
	temp = panda.lookup_gic(vbi.cpu_model)
	if(temp != -1):
		gic_version = temp
	
	vbi.dev_mem_map = panda.libpanda.dev_mem_map
	vbi.file_mem_map = panda.libpanda.file_mem_map
	vbi.irqmap = panda.libpanda.irqmap
	
	for i in range(MAX_MEM_MAPPED_FILES):
		panda.libpanda.file_mem_map[i].opt_fn_str = ffi.NULL
		panda.libpanda.file_mem_map[i].base = 0
		panda.libpanda.file_mem_map[i].size = 0


	for i in range(panda.libpanda.MEM_REGION_COUNT):
		panda.libpanda.dev_mem_map[i].opt_fn_str = ffi.NULL
		panda.libpanda.dev_mem_map[i].base = 0
		panda.libpanda.dev_mem_map[i].size = 0

	mem_str = add_c_string("VIRT_MMIO 0a000000-0a000200;CACHE_CTRL f1008000-f1009000;MPCORE_PERIPHBASE f100c000-f100e000;MEM 00000000-40000000")
	panda.libpanda.parse_mem_map(mem_str)
	vbi.smp_cpus = panda.libpanda.smp_cpus
	
	for i in range(panda.libpanda.smp_cpus):
		cpu_oc = panda.cpu_class_by_name(TYPE_ARM_CPU, vbi.cpu_model)
	
		if not cpu_oc:
			panda.error_report(add_c_string("Unable to find CPU definition"))
			panda.libpanda.exit(0)
		else:
			print("rehosting machine: Adding CPU: %s (%i of %i)" %(ffi.string(vbi.cpu_model), i ,panda.libpanda.smp_cpus)) 
		
		cpuobj = panda.object_new(panda.object_class_get_name(cpu_oc))	

		if panda.object_property_find(cpuobj, add_c_string("has_el3")):
			panda.object_property_set_bool(cpuobj, False, add_c_string("has_el3"));
		
		if panda.object_property_find(cpuobj, add_c_string("reset-cbar")) and vbi.dev_mem_map[panda.libpanda.MPCORE_PERIPHBASE].base:
			panda.object_property_set_int(cpuobj, vbi.dev_mem_map[panda.libpanda.MPCORE_PERIPHBASE].base, add_c_string("reset-cbar"))
		
		if vbi.using_psci:
			print("Using PSCI")
			panda.object_property_set_int(cpuobj, panda.libpanda.QEMU_PSCI_CONDUIT_HVC, add_c_string("psci-conduit"))
			if panda.libpanda.smp_cpus > 0:
				panda.object_property_set_bool(cpuobj, True, add_c_string("start-powered-off"))

		panda.object_property_set_link(cpuobj, ffi.cast("Object*", sysmem), add_c_string("memory"))
		panda.object_property_set_bool(cpuobj, True, add_c_string("realized"))


	machinestate.ram_size = vbi.dev_mem_map[panda.libpanda.MEM].size
	panda.memory_region_allocate_system_memory(ram, ffi.NULL, add_c_string("ram"), machinestate.ram_size)
	panda.memory_region_add_subregion(sysmem, vbi.dev_mem_map[panda.libpanda.MEM].base, ram)

	for i in range(MAX_MEM_MAPPED_FILES):
		if vbi.file_mem_map[i].opt_fn_str != ffi.NULL:
			mr_file = ffi.new("MemoryRegion*")
			assert(mr_file != ffi.NULL)
			panda.memory_region_init_ram_from_file(mr_file, ffi.NULL, vbi.file_mem_map[i].opt_fn_str, vbi.file_mem_map[i].size, False, vbi.file_mem_map[i].opt_fn_str)
			panda.memory_region_add_subregion(sysmem, vbi.file_mem_map[i].base, mr_file)
			print("Mapped %s @ 0x%d8lx" % (vbi.file_mem_map[i].opt_fn_str, vbi.file_mem_map[i].base))
		
	if vbi.dev_mem_map[panda.libpanda.MPCORE_PERIPHBASE].base:
		print("Adding CPU peripheral base @ 0x%d8lx" % vbi.dev_mem_map[panda.libpanda.MPCORE_PERIPHBASE].base)
		panda.create_internal_gic(vbi, s, gic_version)
		
	
	if vbi.dev_mem_map[panda.libpanda.CACHE_CTRL].base:
		print("Adding PL310 @ 0x%d8lx" % vbi.dev_mem_map[panda.libpanda.CACHE_CTRL].base)
		panda.sysbus_create_varargs(add_c_string("l2x0"), vbi.dev_mem_map[panda.libpanda.CACHE_CTRL].base)

	if vbi.dev_mem_map[panda.libpanda.FLASH].base:
		print("Adding flash drive device @ 0x%d8lx" % vbi.dev_mem_map[panda.libpanda.FLASH].base)
		panda.create_one_flash(add_c_string("virt.flash0"), vbi.dev_mem_map[panda.libpanda.FLASH].base, vbi.dev_mem_map[panda.libpanda.FLASH].size, ffi.NULL, sysmem)

	if not vbi.dev_mem_map[panda.libpanda.GIC_DIST].base or vbi.dev_mem_map[panda.libpanda.GIC_CPU].base:
		print("Adding GICv%d @ 0x%d8lx" % (gic_version, vbi.dev_mem_map[panda.libpanda.GIC_DIST].base))
		panda.create_external_gic(vbi, s, gic_version, False)
	

	if vbi.dev_mem_map[panda.libpanda.VIRT_MMIO].base:
		print("Adding VIRT_MMIO @ 0x%d8lx" % vbi.dev_mem_map[panda.libpanda.VIRT_MMIO].base)
		panda.create_virtio_devices(vbi, s.spi)


	print("KERNEL_CMD: %s" % ffi.string(machinestate.kernel_cmdline))
	print("BOARD_ID: %d" % machinestate.board_id)
	
	vbi.bootinfo.ram_size = machinestate.ram_size
	vbi.bootinfo.kernel_filename = machinestate.kernel_filename
	vbi.bootinfo.kernel_cmdline = machinestate.kernel_cmdline
	vbi.bootinfo.initrd_filename = machinestate.initrd_filename
	vbi.bootinfo.nb_cpus = panda.libpanda.smp_cpus
	vbi.bootinfo.board_id = machinestate.board_id

	vbi.bootinfo.is_linux = True
	vbi.bootinfo.loader_start = vbi.dev_mem_map[panda.libpanda.MEM].base
	vbi.bootinfo.firmware_loaded = firmware_loaded

	arm_cpu = ffi.cast("ARMCPU*", panda.libpanda.cpus.tqh_first)

	panda.arm_load_kernel(arm_cpu, ffi.addressof(vbi.bootinfo))
	
	print("during_machine_init done")
	
	
	

	
        

#panda = Panda(qcow="/home/alom/ubuntu-14.04-server-cloudimg-i386-disk1.img")

panda.load_python_plugin(init,"make_configurable_device")
print ("pypanda: loaded plugin -- running")

panda.init()
print ("pypanda: panda initialized")

panda.run()
