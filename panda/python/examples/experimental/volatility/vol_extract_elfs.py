'''
vol_extract_elfs: demo of cool volatility stuff.
By: Luke Craig
'''
from pandare import Panda, blocking
from sys import argv
from time import time
from volatility.framework.objects.utility import array_to_string as a2s
import pdb

arch = "x86_64" if len(argv) <= 1 else argv[1]
extra = "-nographic -chardev socket,id=monitor,path=./monitor.sock,server,nowait -monitor chardev:monitor -serial telnet:127.0.0.1:4444,server,nowait  -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22 -cdrom /home/luke/workspace/qcows/instance-1-cidata.iso"
qcow = "/home/luke/workspace/qcows/instance-1.qcow2"
panda = Panda(arch=arch,qcow=qcow,extra_args=extra,mem="1G")

timechange = 5
oldtime = time()
PT_LOAD = 1

'''
read_elf: This takes a task, iterates over its vmas, and reads the sections into a byte string.
It then returns the byte string.
'''
def read_elf(vmlinux, task, name, proc_layer):
	proc_layer_name = proc_layer._name
	# get program sections
	vmas = task.mm.get_mmap_iter()
	elf_vmas = list(filter(lambda vma: name in vma.get_name(vmlinux.context, task), vmas))
	elf_vma_start = min([vma.vm_start for vma in elf_vmas])
	elf_hdr_type = vmlinux.get_type('elf64_hdr')
	elf_phdr_type = vmlinux.get_type('elf64_phdr')
	elf_shdr_type = vmlinux.get_type('elf64_shdr')

	symbol_name = vmlinux.symbol_table_name + "!" + "elf64_hdr"
	elf_hdr = vmlinux._context.object(object_type=symbol_name,layer_name=proc_layer_name,offset=elf_vma_start)
	ident = elf_hdr.e_ident
	if not (ident[0] == 0x7f and ident[1] == 0x45 and ident[2] == 0x4c and ident[3] == 0x46):
		print("Not an actual ELF. Sorry...")
		return 0

	sections = {}
	for i in range(elf_hdr.e_phnum):
		symbol_name = vmlinux.symbol_table_name + "!" + "elf64_phdr"
		section = vmlinux._context.object(object_type=symbol_name,layer_name=proc_layer_name,offset=elf_vma_start+elf_hdr.e_phoff+(elf_phdr_type.size*i))
		# borrowed from volatility get_elf
		start = section.p_vaddr
		sz = section.p_memsz
		end = start + sz

		if start % 4096:
			start = start & ~0xfff

		if end & 4096:
			end = (end & ~0xfff) + 4096

		real_size = end - start
		if real_size <= 0 or real_size > 100000000:
			continue
		sections[start] = real_size
	ret = b""
	for start in sorted(sections.keys()):
		read_size = sections[start]
		ret += proc_layer.read(start,read_size,pad=True)
	return ret

'''
This iterates the task list, finds the first bash process, establishes a process layer to
read from, and writes it out to disk
'''
@panda.cb_asid_changed()
def on_asid_change(env, old_asid, new_asid):
	global oldtime, timechange
	if time() - oldtime > timechange:
		pdb.set_trace()
		vmlinux = panda.get_volatility_symbols()
		init_task = vmlinux.object_from_symbol(symbol_name = "init_task")

		# get first bash process
		bash = list(filter(lambda task: a2s(task.comm) == "bash", init_task.tasks))[0]

		# set up process layer
		proc_layer_name = bash.add_process_layer()
		proc_layer = vmlinux.context.layers[proc_layer_name]

		# read the ELF from memory
		bash_file = read_elf(vmlinux, bash, "/bin/bash", proc_layer)

		# write the ELF
		open("./cool_extracted_bash", "wb").write(bash_file)

		oldtime = time()
	return 0

@blocking
def init():
	panda.revert_sync("cmdline")


panda.queue_async(init)
panda.run()
