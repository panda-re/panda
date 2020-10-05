import gdb
import sys

file_out = sys.stdout

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
    
    arch = gdb.execute('printf "%s", init_uts_ns->name->machine',to_string=True)
    
    if arch == "mips":
        i = 1
        while True:
            output = gdb.execute(f"info symbol ((uint32_t (*)[300]) sys_call_table)[0][{i}]",to_string=True)
            if "No symbol matches" in output:
                break
            syscall_name = output.split()[0]
            # ptype is of form "type = void (void, void, void)", so we get rid of "type ="
            syscall_type = gdb.execute(f"ptype {syscall_name}",to_string=True)[len("type = "):]
            # put syscall name in the "void (void, void, void)" type
            syscall_info = syscall_type.replace("(", f"{syscall_name}(").strip()
            # print out information
            print(f"{i} {syscall_info};",file=file_out)
            i += 1

    else:
        syscall_table_len = int(gdb.execute('printf "%d", sizeof(sys_call_table)/sizeof(*sys_call_table)',to_string=True))
    
        for i in range(syscall_table_len):
            # get the symbol name from the sys_call_table at i. Split to get just the name.
            syscall_name = gdb.execute(f"info symbol *sys_call_table[{i}]",to_string=True).split()[0]
            if "ptregs_" in syscall_name:
                # in older kernels ptregs_execve is #defined to sys_execve. We just replace it.
                syscall_name = syscall_name.replace("ptregs_","sys_") # edge case in older kernels 
    
            # ptype is of form "type = void (void, void, void)", so we get rid of "type ="
            syscall_type = gdb.execute(f"ptype {syscall_name}",to_string=True)[len("type = "):]
    
            # put syscall name in the "void (void, void, void)" type
            syscall_info = syscall_type.replace("(", f"{syscall_name}(").strip()
    
            # print out information
            print(f"{i} {syscall_info};",file=file_out)
    if file_out != sys.stdout:
      file_out.close()


# This registers our class to the gdb runtime at "source" time.
SyscallTable()
