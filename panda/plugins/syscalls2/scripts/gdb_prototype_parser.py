import gdb
import sys
import ipdb
import re

file_out = sys.stdout

def parse_syscall_define(source):
  if "SYSCALL_DEFINE0" in source:
      args = "void"
  else:
      matches = re.search("SYSCALL_DEFINE\d[(][^)]+[)]", source, re.DOTALL)
      if not matches:
          matches = re.search("SYSCALL_DEFINE[(][^)]+[)][(][^)]+[)]",source, re.DOTALL)
          if matches:
              define = matches[0]
              begin_args = define.find(")(")
              return define[begin_args+1:-1]
          else:
              return ""
      define = matches[0]
      begin_args = define.find("(")
      # parse inside of arguments (.*) 
      arg_full = define[begin_args+1:-1]
      arg_no_name = arg_full.split(",")[1:]
      args = ""
      for j in range(len(arg_no_name))[::2]:
          needcomma = "," if j != len(arg_no_name) - 2 else ""
          args += f"{arg_no_name[j]} {arg_no_name[j+1]}{needcomma}" 
  return args

def parse_regular_function(define):
  firstparen = define.find("(")   
  if firstparen == -1:
      return ""
  args = define[firstparen+1:-1]
  return args
    

class SyscallTable(gdb.Command):
  def __init__(self):
    super(SyscallTable, self).__init__("get_syscall_table", gdb.COMMAND_DATA)

  def invoke(self, arg, from_tty):
    global file_out
    if arg:
      file_out = open(arg, "w+")  
      print(f"Printing output to {arg}") 
        
    try:
      sys_call_table = gdb.execute("p &sys_call_table",to_string=True)
    except:
      print("FAIL. Cant find syscall table. Make sure you compiled your kernel with CONFIG_DEBUG_INFO")
      file_out.close()
      return

    syscall_table_len = int(gdb.execute('printf "%d", sizeof(sys_call_table)/sizeof(*sys_call_table)',to_string=True))

    for i in range(syscall_table_len):
        # get the symbol name from the sys_call_table at i. Split to get just the name.
        syscall_name = gdb.execute(f"info symbol *sys_call_table[{i}]",to_string=True).split()[0]

        if "ptregs_" in syscall_name:
            # in older kernels ptregs_execve is #defined to sys_execve. We just replace it.
            syscall_name = syscall_name.replace("ptregs_","sys_") # edge case in older kernels 
                
        symbol = gdb.lookup_global_symbol(syscall_name)
        if not symbol:
            #print(f"{i} Continued for {syscall_name}")
            continue
        fname = symbol.symtab.fullname()
        source = open(fname,"r").read().replace("\t","")
        if "sys_ni_syscall" in source:
            continue
        args = parse_syscall_define(source)
        if not args:
            def1 = re.search(f"{syscall_name}[(][^)]+[)]", source, re.DOTALL)
            if not def1:
                ipdb.set_trace()
                print(f"Couldn't find anything for {syscall_name}")
                continue

            args = parse_regular_function(def1[0])
            if not args:
                ipdb.set_trace()
                print(f"Couldn't find anything for {syscall_name}")
                continue

        # ptype is of form "type = void (void, void, void)", so we get rid of "type ="
        #ipdb.set_trace()
        syscall_type = gdb.execute(f"ptype {syscall_name}",to_string=True)[len("type = "):]
        if len(syscall_type.split()) < 1:
            ipdb.set_trace()
        rettype = syscall_type.split()[0]

        # put syscall name in the "void (void, void, void)" type
#        syscall_info = syscall_type.replace("(", f"{syscall_name}(").strip()

        # print out information
        args = args.replace("\n","").replace("\r","")
        print(f"{i} {rettype} {syscall_name}({args});",file=file_out)
    if file_out != sys.stdout:
      file_out.close()


# This registers our class to the gdb runtime at "source" time.
SyscallTable()
