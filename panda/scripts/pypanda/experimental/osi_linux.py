'''
attempt at getting osi_linux to function in pure python.
abandoned when the C translation worked.
'''
from pypanda import *
from qcows import get_qcow
from sys import argv

def read_kernelinfo(kernelinfo, config):
	# just easier to get these out in the open
	name = kernelinfo.name
	version = kernelinfo.version
	task = kernelinfo.task
	cred = kernelinfo.cred
	mm = kernelinfo.mm
	vma = kernelinfo.vma
	fs = kernelinfo.fs
	qstr = kernelinfo.qstr
	path = kernelinfo.path


	# decode linux version from name string
	from re import findall
	name = ffi.new("char[]", bytes(config['name'],'utf-8'))
	linux_version = findall(r'(?:(\d+\.(?:\d\.)*\d+))',config['name'])[0] # regex SO #24629867
	version.a, version.b, version.c = (int(i) for i in linux_version.split("."))

	task.init_addr = int(config['task.init_addr'])
	task.size =	int(config['task.size'])

	if version.a > 2 and version.b > 4 and version.c > 254:
		task.tasks_offset = int(config['task.tasks_offset'])
		task.task_offset = int(config['task.task_offset'])
		task.group_leader_offset = int(config['task.group_leader_offset'])
		task.stack_offset = int(config['task.stack_offset'])
		task.real_cred_offset = int(config['task.real_cred_offset'])
		task.cred_offset = int(config['task.cred_offset'])
		task.real_parent_offset = int(config['task.real_parent_offset'])
		task.parent_offset = int(config['task.parent_offset'])
		cred.uid_offset = int(config['cred.uid_offset'])
		cred.gid_offset = int(config['cred.gid_offset'])
		cred.euid_offset = int(config['cred.euid_offset'])
		cred.egid_offset = int(config['cred.egid_offset'])
		fs.f_path_dentry_offset = int(config['fs.f_path_dentry_offset'])
		fs.f_path_mnt_offset = int(config['fs.f_path_mnt_offset'])
		fs.fdt_offset = int(config['fs.fdt_offset'])
		fs.fdtab_offset = int(config['fs.fdtab_offset'])
		path.d_dname_offset = int(config['path.d_dname_offset'])
	elif version.a > 2 and version.b > 4 and version.c > 0:
		task.p_opptr_offset = int(config['task.p_opptr_offset'])
		task.p_pptr_offset = int(config['task.p_pptr_offset'])
		task.next_task_offset = int(config['task.next_task_offset'])
		fs.f_dentry_offset = int(config['fs.f_dentry_offset'])
		fs.f_vfsmnt_offset = int(config['fs.f_vfsmnt_offset'])
	
	task.thread_group_offset = int(config['task.thread_group_offset'])
	task.pid_offset = int(config['task.pid_offset'])
	task.tgid_offset = int(config['task.tgid_offset'])
	task.mm_offset = int(config['task.mm_offset'])
	task.comm_offset = int(config['task.comm_offset'])
	task.comm_size = int(config['task.comm_size'])
	task.files_offset = int(config['task.files_offset'])
	# read mm information
	mm.size = int(config['mm.size'])
	mm.mmap_offset = int(config['mm.mmap_offset'])
	mm.pgd_offset = int(config['mm.pgd_offset'])
	mm.arg_start_offset = int(config['mm.arg_start_offset'])
	mm.start_brk_offset = int(config['mm.start_brk_offset'])
	mm.brk_offset = int(config['mm.brk_offset'])
	mm.start_stack_offset = int(config['mm.start_stack_offset'])
	# read vma information
	vma.size = int(config['vma.size'])
	vma.vm_mm_offset = int(config['vma.vm_mm_offset'])
	vma.vm_start_offset = int(config['vma.vm_start_offset'])
	vma.vm_end_offset = int(config['vma.vm_end_offset'])
	vma.vm_next_offset = int(config['vma.vm_next_offset'])
	vma.vm_file_offset = int(config['vma.vm_file_offset'])
	vma.vm_flags_offset = int(config['vma.vm_flags_offset'])
	# read fs information
	fs.f_pos_offset = int(config['fs.f_pos_offset'])
	fs.fd_offset = int(config['fs.fd_offset'])
	# read qstr information
	qstr.size = int(config['qstr.size' if 'qstr.size' in config else 'path.qstr_size'])
	#qstr.name_offset = int(config['qstr.name_offset']) This one I have no idea. nothing current works
	# read path information
	path.d_name_offset = int(config['path.d_name_offset'])
	path.d_iname_offset = int(config['path.d_iname_offset'])
	path.d_parent_offset = int(config['path.d_parent_offset'])
	path.d_op_offset = int(config['path.d_op_offset'])
	path.mnt_root_offset = int(config['path.mnt_root_offset'])
	path.mnt_parent_offset = int(config['path.mnt_parent_offset'])
	path.mnt_mountpoint_offset = int(config['path.mnt_mountpoint_offset'])
	# no need for a return. It fills the struct passed.

def process_name_convert(name):
	a = ""
	for i in range(16):
		char = name[i].decode()
		if ord(char) == 0:
			break
		a += char
	return a	


#def read_vfsmount_name(cpustate, vfsmount):
#	name = ffi.new("char*")
#	pcomp = ffi.new("char*")
#	pcomps = []
#	
#	current_vfsmount_parent = vfsmount
#	current_vfsmount = ffi.NULL
#
#	while current_vfsmount_parent != current_vfsmount:
#		current_vfsmount = current_vfsmount_parent
#		current_vfsmount_dentry = read_current_vfsmount_dentry
#		current_v
#


class osi_linux:
	def __init__(self, panda, kconf_file, kconf_group):
		self.panda = panda
		from configparser import ConfigParser
		config = ConfigParser()
		if len(config.read(kconf_file)) ==  0:
			print("Could not read file %s" % kconf_file)
			return
		if kconf_group not in config:
			print("Could not find group %s in file %s" % (kconf_group, kconf_file))
			return
		self.kinfo = ffi.new("struct kernelinfo*")
		read_kernelinfo(self.kinfo,config[kconf_group])
		version = self.kinfo.version
		version.a,version.b,version.c = 2, 3, 23
		self.kprofile = "kernel2.4" if version.a <= 2 \
						and version.b <=4 and version.c <=254 else "default"
	
	def get_file_name(self, cpustate, file_struct_ptr):
		name = ffi.new("char*")
		fs = self.kinfo.fs
		file_dentry = offset_get_target_ptr(cpustate, file_struct_ptr,fs.f_path_dentry_offset)
		file_mnt = offset_get_target_ptr(cpustate, file_struct_ptr, fs.f_path_mnt_offset) 

		if file_dentry == ffi.NULL:
			print("Could not read file_dentry")
			return ffi.NULL
		elif file_mnt == ffi.NULL:
			print("Could not read file_mnt")
			return ffi.NULL	

	def get_name(self, cpustate, task_struct):
		task = self.kinfo.task
		size = ffi.cast("target_ulong", task.comm_size)
		faddr = ffi.cast("target_ulong", task_struct + task.comm_offset)
		ret = ffi.new("char[]", task.comm_size)
		self.panda.virtual_memory_read(cpustate,faddr,ret,size)
		return ret

	def fill_osiproc(self,cpustate,proc,task_addr):
		task = self.kinfo.task
		proc.taskd = task_addr 
		proc.name = self.get_name(cpustate,task_addr)
		#ts = self.offset_get_target_ptr(cpustate, task_addr, task.tgid_offset)
		#proc.pid = ffi.cast("uint32_t*", ts)[0]	
		proc.ppid = 0
		proc.pages = ffi.NULL
		proc.asid = 0


	def get_current_process(self, cpustate):
		p = ffi.new("struct osi_proc_struct*")
		kernel_esp = self.panda.current_sp(cpustate)
		page_size = ffi.cast("target_ulong", 4096)
		addr = self.panda.libpanda.panda_current_sp_masked_pagesize_external(cpustate, page_size)
		ts = self.offset_get_target_ptr(cpustate, addr, self.kinfo.task.task_offset)
		td = ffi.cast("target_ulong*", ts)
		self.fill_osiproc(cpustate,p,td[0])		
		return p

	def get_process_info(cpustate, stype):
		ret = ffi.new(stype)
		ts_first = self.kinfo.task.init_addr
		kernel_esp = self.panda.current_sp(cpustate)
	
	# equivalent for IMPLEMENT_OFFSET_GET.
	# type removed because it's always target_ptr_t in the code
	def offset_get_target_ptr(self,cpustate, addr, offset):
		ret = ffi.new("char[]",4)
		size = ffi.cast("target_ptr_t", ffi.sizeof(ret))
		faddr = ffi.cast("target_ptr_t", addr+offset)
		self.panda.virtual_memory_read(cpustate,faddr,ret,size)
		return ret 
	
