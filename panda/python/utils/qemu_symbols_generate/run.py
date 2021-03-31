import pdb

# add manually. 1st field is the name for CPU*ARCH*State. 2nd is bits. 3rd is path to libpanda*.so
archs = [
	("X86", 32,"/i386-softmmu/libpanda-i386.so"),
	("X86", 64, "/x86_64-softmmu/libpanda-x86_64.so"),
	("ARM", 32, "/arm-softmmu/libpanda-arm.so"),
	("ARM", 64, "/aarch64-softmmu/libpanda-aarch64.so"),
	("PPC", 32, "/ppc-softmmu/libpanda-ppc.so"),
	("PPC", 64, "/ppc64-softmmu/libpanda-ppc64.so")
]

panda_base = "/build"

# REPLACE ME. do not use the ubuntu version from dwarves. build it.
# https://kernel.googlesource.com/pub/scm/devel/pahole/pahole
pahole_path = "/pahole/build/pahole" 

'''
This function removes anything that we can't parse in cffi later.
In particular, it removes class item identifiers
'''
def line_passes(line):
	# error messages and class identifiers
	banned = ["die__", "public:", "private:", "protected:","DW_AT_<"]
	for i in banned:
		if i in line:
			return False
	return True

'''
Here we strip enums out of classes.
We do this because enums defined in classes cant be parsed by cffi.
'''
def extract_enum(i):
	lines = [i for i in i.split("\n")]
	out_lines = []
	enums = []
	in_enum= -1
	for line in lines:
		if "enum" in line and "{" in line:
			in_enum = 1
			#enums.append(line)
		elif in_enum != -1:
			in_enum += 1
			#enums.append(line)
			if  "}" in line:
				in_enum = -1
		else:
			out_lines.append(line)
	return "\n".join(out_lines) + "\n"+"\n".join(enums)


'''
This function replaces types with void. We use this only on *very*
problematic structs. Usually those structs are actually classes
represented as structs.
''' 
def strip_struct(output):
	lines = [line for line in output.split("\n")]
	for i in range(len(lines))[1:-1]:
		if len(lines[i].strip()) > 0:
			precomments = lines[i].split("/*")[0]
			objs = precomments.split()
			if "*" in objs:
				objs[0] = "void"
				for j in range(len(objs))[1:]:
					if "*" in objs[j]:
						break
					else:
						objs.pop(j)
			lines[i] = "\t"+" ".join(objs)
	return "\n".join(lines)
				

'''
Uses pahole to generate struct.
'''
def get_struct(name, pahole_path, elf_file):
	from subprocess import getoutput
	out =getoutput(pahole_path+" --classes_as_structs --suppress_aligned_attribute --suppress_force_paddings --class_name="+name+ " "+elf_file )
	# object refers to a class-like object I didn't want to deal with
	problematic = ["Object"] 

	out = out.replace("class", "struct")
	out = out.replace("TCGLLVMTranslator", "void")
	out = out.replace("__int128 unsigned", "Int128") # cffi doesn't support 128 bit 
	out = "\n".join([i for i in out.split("\n") if line_passes(i)])
	out = extract_enum(out)
	if name in problematic:
		out = strip_struct(out)
	if not out.strip():
		pdb.set_trace()
		print("empty")
	print("struct "+name)
	print(out)
	return out

'''
Identifies basic types or previously defined types as means of determining new dependencies.
'''
def is_basic_type(a,base):
	return a == "void" or "int" in a or "bool" in a.lower() or a in base

'''
An attempt to use a predefined C alphabet on types to get correct type out.
'''
def name_without_ptr(a):
	# specifically we're getting rid of *, but this is a good catch
	from string import ascii_letters, digits
	alphabet = ascii_letters+digits+"_" # alphabet for names
	return "".join([i for i in a if i in alphabet]) 


'''
Represents individual structs. Maintains their data and returns it in a format the header
can understand and render. Also maintains dependencies.
'''
class Struct(object):
	def __init__(self, name, elf, pahole_path):
		self.name = name
		self.elf = elf
		self.pahole_path = pahole_path
		cont = get_struct(name, pahole_path, elf)
		# get rid of blank lines and (some) pahole warnings
		self.content = "\n".join([line for line in cont.split("\n") if line.strip() and "lexblock__recode_dwarf_types" not in line])
		if "lexblock__recode_dwarf_types" in self.content: # Failed to remove warnings
			print("Invalid structure:", self.content)
			raise RuntimeError("Trying to parse a pahole error as a struct. Aborting")

		self.circular_depends = []
		self.depends = []

	def add_dependency(self, dependency):
		self.depends.append(dependency)
	
	def add_circular_dependency(self, dependency):
		if dependency in self.depends:
			self.depends.remove(dependency)
		if dependency not in self.circular_depends:
			self.circular_depends.append(dependency)
	
	def __str__(self):
		content = "struct "+self.name+";\ntypedef struct "+self.name +" " + self.name + ";\n"
		for item in self.circular_depends:
			content += "struct "+item.name+";\ntypedef struct "+item.name + " "+item.name +";\n"
		content += self.content + "\n"
		return content
			

'''
HeaderFile is the representation of the generated header file in python. A header file is made up
of a base of assumptions and structs. The header file is "rendered" by starting with the assumptions
and inserting structs.

A headerfile can validate itself by rendering with no errors in CFFI and correctly creating the required
structs without error. Otherwise it returns an error.
'''
class HeaderFile(object):
	def __init__(self, arch, base, pahole_path, elf):
		self.arch = arch
		self.structs = {} # mapping of struct name to struct
		self.lines = {}  # mapping of line # to struct for debugging
		self.base = base
		self.pahole_path = pahole_path
		self.elf = elf

	# Add struct to structs list
	def add_struct(self, struct_name):
		if struct_name not in self.structs:
			self.structs[struct_name] = Struct(struct_name, self.elf, self.pahole_path)
		else:
			print("Got duplicate")
			pdb.set_trace()

	def render(self):
		return self.__str__()
	# output header as text.
	def __str__(self):
		self.lines = {}
		struct_ordered_list = []

		# offset our structs list by our base
		self.current_line_num = self.base.count("\n")
		
		# It helps our process to sort by lowest depencency number
		struct_unordered_list = list(self.structs.values())
		struct_unordered_list.sort(key=lambda x: len(x.depends))
		'''
		this method attempts to insert structs into the ordered list
		It does this by first checking that all dependencies are satisfied.
		If not it attempts to insert its dependencies.
		It maintains a call list to find loops. If it finds loops it breaks the chain.
		'''
		def insert_struct(struct, marked):
			global current_line_num
			m = marked.copy()
			if struct in m:
				print("loop detected:"+" ".join([i.name for i in m]))
				# break loops by finding the first loop node and breaking the dependency to its next item
				print("breaking loop")
				next_item = m[m.index(struct)+1]
				struct.add_circular_dependency(next_item)
			m.append(struct)
			depends = struct.depends
			for sd in depends:
				if sd not in struct_ordered_list:
					insert_struct(sd,m)
			if struct not in struct_ordered_list:
				struct_ordered_list.append(struct)
				lines = str(struct).count("\n")
				for i in range(lines): # gives us a mapping of line num to struct
					self.lines[self.current_line_num+i] = struct
				self.current_line_num += lines
			
		for struct in struct_unordered_list:
			insert_struct(struct, [])

		# This insures we didn't break anything along the way.
		assert(len(struct_ordered_list) == len(struct_unordered_list))
		return self.base + "".join([str(x) for x in struct_ordered_list])
	
	'''
	This function identifies the struct that needs to be processed next.
	'''
	def get_name(self,lst):
		if "(*" in "".join(lst): # is a function
			# This one is complicated. It could be missing
			# the return type, or any of the arguments.
			# All this to say you may have to implement it.
			# Better than I did anyway.
			a = "".join(lst)
			ret = name_without_ptr(a.split(")(")[0].split("(*")[0])
			args = [name_without_ptr(i) for i in a.split(")(")[1].split(",")]
					
			if not is_basic_type(ret,self.base) and ret not in self.structs:
				return ret
			else:
				for i in range(len(args)):
					if args[i] not in self.structs:
						if not is_basic_type(args[i],self.base):
							return args[i]
		bad = ["const"]
		if lst[0] in bad:
			return lst[1]
		return lst[0]

	'''
	This function parses various error messages.
	'''	
	def parse_error_msg(self, e):
		q = str(e)
		print(q)
		if e.__class__.__name__ == "TypeError":
			split = q.split("'")
			former = split[1].split(".")[0]
			former_obj = self.structs[former]
			former_line = None
			for line in self.lines.keys():
				if self.lines[line] == former_obj:
					former_ret = line
			latter = split[3].split()[1]
			return latter, former_ret
		elif e.__class__.__name__ == "ValueError":
			split = q.split("'")
			struct = split[1].split()[1]
			# It has to be before CPUState
			former = self.structs["CPUState"]
			fline = 0
			for line in self.lines.keys():
				if self.lines[line] == former:
					fline = line
			return struct, fline
		else:
			try:
				missing = q.split('"')[1]
			except:
				pdb.set_trace()
			missing_type = self.get_name(missing.split())
			if missing_type == "void":
				pdb.set_trace()
			line = q.split('<cdef source string>:')[1].split(':')[0]
		return missing_type, int(line)

	'''
	This function attempts to validate the header by using cdef and creating new structs.
	If there is an error it will attempt to parse it and return that.
	'''
	def validate(self):
		from cffi import FFI
		global comptries
		comptries += 1
		try:
			self.ffi = FFI()
			self.ffi.cdef(str(self))
			cpustate = self.ffi.new("CPUState*")
			self.ffi.new("CPU"+self.arch+"State*")
			self.ffi.new("TranslationBlock*")
			self.ffi.new("MachineState*")
			self.ffi.new("Monitor*")
			return False
		except Exception as e:
			return self.parse_error_msg(e)
	


'''
This function attempts to create, validate, and write a header file based on the required information
'''
def generate_config(arch, bits, pahole_path, elf_file):
	# a bunch of host assumptions. Including a blatantly wrong one. Though I can't seem to fix it.
	assumptions = open("./assumptions.h","r").read()
	base = "typedef uint"+str(bits)+"_t target_ulong;\n"+assumptions
	global header
	header = HeaderFile(arch, base, pahole_path, elf_file)
	# the truth of the matter is we don't need 1000s of QEMU structs. We need 3.
	# We also need the tree created by references to those.
	struct_list = ["QemuThread", "QemuCond", "qemu_work_item","CPUAddressSpace",
	"GDBRegisterState", "CPUState", "TranslationBlock", "MachineState", "Monitor"]

	for struct in struct_list:
		header.add_struct(struct)

	# correction to make this not architecture neutral
	CPUState = header.structs["CPUState"]
	CPUState.content = CPUState.content.replace("void *                     env_ptr;", "CPU"+arch+"State *                     env_ptr;")
	previous = "CPUState"
	loopcounter = 0
	while True:
		valid = header.validate()
		if valid:
			missing, line = valid
			if missing == previous:
				loopcounter += 1
				print("Looks like you're in a loop!")
				if loopcounter >= 10:
					pdb.set_trace()
			else:
				loopcounter = 0
			previous = missing
			print("It seems to have a dependency from "+header.lines[line].name +" on " + missing)
			if missing not in header.structs: # truly missing
				print("adding "+missing)
				header.add_struct(missing)
#			print("adding dependency")
			header.lines[line].add_dependency(header.structs[missing])
		else:
			break
	
	OUT_FILE_NAME = "/output/panda_datatypes_"+arch+"_"+str(bits)+".h"
	with open(OUT_FILE_NAME,"w") as f:
		f.write(header.render())
	print("Finished. Content written to "+OUT_FILE_NAME)

comptries = 0

for arch in archs:
	generate_config(arch=arch[0], bits=arch[1], pahole_path=pahole_path, elf_file=panda_base+arch[2])

print("Number of compilation tries: " + str(comptries))
