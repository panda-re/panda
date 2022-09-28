#!/usr/bin/env python3
from pandare import PyPlugin

#TODO: don't require /proc/kallsyms, offer option to extract from running guest
#       -we do want to leave the file as an option in case it must be extracted
#        statically from vmlinu*
kallsyms="./kallsyms_i386_generic"

class KernelInfo(PyPlugin):
    def __init__(self, panda):
        self.kinfo = {}
        self.syms = {}
        self.pids = [] #List of pids we'll use to derive task_struct info
        self.parent_pid = None #Parent of those processes
        self.parent_task = None #Parent of those processes
        self.task_struct_ptrs = []
        self.init = None #the task_struct for init (pid 1), not init_task (pid 0)
        self.child1_task = None
        
        self.panda = panda
        self.ptr_size = int(panda.bits/8)
        self.endian = "little" #TODO implement this
        kallsyms_file =  self.get_arg("kallsyms")

        print("Loading kallsyms from: ", kallsyms_file)
        self.parse_kallsyms(kallsyms_file)

        #FIXME: For now, we're reading from /proc/slabinfo
        #       Can do kmem_cache_create to get sizeof() fields if we want to 
        #       track boot
        @panda.hook(self.syms["kmem_cache_create"])
        def kmem_cache_create(cpu, tb, h):
            ptr = panda.arch.get_reg(cpu, 'eax')
            try:
                s = self.panda.read_str(cpu, ptr, 256)
            except ValueError:
                s = ERROR
                return

            print(f"kmem_cache_create: {s}, {ptr:#x}")
            
            if "task_struct" in s:
                size = panda.arch.get_reg(cpu, 'edx')
                print(f"kmem_cache_create sizeof(task_struct): {size}")

        @panda.hook(self.syms["dup_fd"])
        def dup_fd(cpu, tb, h):
            #Only do this once we've processed the task list and not again
            if "task.tasks_offset" not in self.kinfo or "task.files_offset" in self.kinfo:
                return
            
            files_struct_ptr = panda.arch.get_reg(cpu, 'eax')
            print("Saw dup_fd after task list a was processed ", end='')
            print(f"files_struct: {files_struct_ptr:#x}")
            #We should be back in the parent 
            offset = 0
            while offset < self.kinfo["task.size"]:
                #This assumes our fields of interest are word aligned
                value = self.read_int(cpu, self.parent_task + offset)
                if value == files_struct_ptr:
                    print(f"Found files_struct at {offset}")
                    self.kinfo["task.files_offset"]=offset
                    break
                offset += self.ptr_size

        #Could be useful in the future
        #@panda.hook(self.syms["task_stats_exit"])
        def task_stats_exit(cpu, tb, h):
            task_ptr = panda.arch.get_reg(cpu, 'eax')
            print(f"task_stats_exit: {task_ptr:#x}")
        
        #@panda.hook(self.syms["proc_pid_auxv"])
        #Exported kernel function, so we expect API to be stable
        #Trigger this with a read of /proc/self/syscall
        #Don't want to rely on stack pointer, etc... for getting task structs
        @panda.hook(self.syms["task_current_syscall"])
        def task_current_syscall(cpu, tb, h):
            #TODO: new convention for args: kernel_function
            task_ptr = panda.arch.get_reg(cpu, 'eax')
            print(f"task_current_syscall: {task_ptr:#x}")

            #Getting task.per_cpu_offset_0_addr
            #addr = self.kinfo['task.per_cpu_offsets_addr'] 
            #self.kinfo["task.per_cpu_offset_0_addr"] = self.read_int(cpu, addr)

            if self.parent_pid:
                offset = 0
                while offset < self.kinfo["task.size"]:
                    #This assumes our fields of interest are word aligned
                    value = self.read_int(cpu, task_ptr + offset)

                    #
                    #Find pid offset using the user_prog parent process
                    #
                    if value in self.pids or value == self.parent_pid:
                        #TODO: make less fragile since pids may be low at boot
                        #      Hack for now is just to spawn multipe processes
                        if value == self.parent_pid and not self.parent_task:
                            init_pid_p = self.init + offset
                            init_pid = self.read_int(cpu, init_pid_p)
                            if init_pid == 1:
                                self.parent_task = task_ptr
                                self.kinfo["task.pid_offset"]=offset
                                print(f"Found user_prog pid  {value} at {offset}")
                            else:
                                print(f"Tried {offset} as pid but got init_pid = {init_pid}")
                                init_pid = self.read_int(cpu, init_pid_p - offset)
                                print(f"reading init_p: {init_pid:#x}")
                        #TODO: can assume tgid comes after pid and will be same 
                        #else:
                        #    print(f"{value}: Found new pid_offset: {offset}")
                            #self.kinfo["task.tgid_offset"]=offset

                    if not self.parent_task or len(self.pids) != 2:
                        #The child processes don't exist yet
                        offset += self.ptr_size
                        continue 

                    
                    #Find tasks, which is a: struct list_head *next, *prev;
                    #The assumption we're making here is that a higher pid 
                    #will be the next process

                    #At this point, we know the pid offset
                    pid = self.read_int(cpu, task_ptr+self.kinfo["task.pid_offset"])

                    if pid not in self.pids:
                        offset += self.ptr_size
                        continue

                    #
                    #Find parent_offset
                    #
                    if value == self.parent_task:
                        print(f"Found parent of {pid} at {offset}!")
                        if "task.real_parent_offset" not in self.kinfo:
                            #ASSUMPTION: real_parent comes first
                            self.kinfo["task.real_parent_offset"]=offset
                        else:
                            self.kinfo["task.parent_offset"]=offset
                        #Can verify these with pid offsets if we want 

                    #
                    #Find tasks, the task list
                    #
                    if pid == self.pids[0] and self.child1_task is None:
                        self.child1_task = task_ptr
                        print(f"Child 1's task: {task_ptr}")
 
                    if pid == self.pids[1] and "task.tasks_offset" not in self.kinfo:
                        #Second child's prev should be first child, probably

                        #This is a bit convoluted. The list_head is *next
                        #so if we're working with prev, we need to add back one
                        #ptr
                        if (value-offset+self.ptr_size) == self.child1_task:
                            print(f"Found offset for prev: {offset}")
                            self.kinfo["task.tasks_offset"] = offset-self.ptr_size
                            self.process_list(cpu)

                    #END OF BIG MEMORY READ LOOP
                    offset+=self.ptr_size
            else:
                #no parent_pid yet - so we are init (/proc/1)
                self.init = task_ptr
                pass #will need to do something here to find init_task
            
            #White box testing stuff for i386 generic kernel
            #next_task = self.read_int(cpu, task_ptr+632) 
            #prev_task = self.read_int(cpu, task_ptr+636) 
            #pid = self.read_int(cpu, task_ptr+788)
            #print(f"{task_ptr:#x} ({pid}): next: {next_task:#x} prev: {prev_task:#x}")

        #Cheap and dirty way to receive information from the user program
        @panda.ppp("syscalls2", "on_sys_write_return")
        def on_write(cpu, pc, fd, buf, count):
            try:
                s = self.panda.read_str(cpu, buf, count)
            except ValueError:
                return

            if s.startswith("KERNELINFO:"):
                #Direct kernelinfo output from userprog, read it in
                split = s.split()
                self.kinfo[split[1]] = int(split[2])

            if s.startswith("PANDA:"):
                split = s.split()
                #Our user program forks two children, we'll use these to
                #find properties in the task structs
                if split[1] == "pids:":
                    self.pids.append(int(split[2]))
                    self.pids.append(int(split[3]))
                    print(f"User prog created processes: {self.pids}")

                if split[1] == "parent_pid:":
                    self.parent_pid = int(split[2])
                    print(f"Parent pid: {self.parent_pid}")
                    

    def parse_kallsyms(self, filename):
        with open(filename, 'r') as f:
            for line in f.readlines():
                #Fragile parsing:
                addr, sym_type, name  = line.split()[:3]
                addr = int(addr,base=16)
                if "task_current_syscall" == name:
                    self.syms[name] = addr
                if "__put_task_struct" == name:
                    self.syms[name] = addr
                if "arch_dup_task_struct" == name:
                    self.syms[name] = addr
                if "current_task" == name:
                    self.kinfo['task.current_task'] = addr
                if name == "init_task":
                    #TODO: if this symbol doesn't exit, we'll have to get 
                    #      pid 0's address from the list
                    self.kinfo['task.init_addr'] = addr
                if name == "__per_cpu_offset":
                    self.kinfo['task.per_cpu_offsets_addr'] = addr
                if name == "arch_task_struct_size":
                    self.syms[name]  = addr
                if name == "kmem_cache_create":
                    self.syms[name]  = addr
                if name == "task_stats_exit":
                    self.syms[name]  = addr
                if name == "dup_fd":
                    self.syms[name]  = addr
                if name == "taskstats_exit":
                    #Same as above, higher kernel versions
                    self.syms["task_stats_exit"] = addr



        #print("Found symbols: ",self.syms)
    def read_int(self, cpu, read_addr):
        data = self.panda.virtual_memory_read(cpu, read_addr, self.ptr_size)
        return int.from_bytes(data,byteorder=self.endian)

    def next_task(self, cpu, task):
        offset = self.kinfo["task.tasks_offset"]        
        return self.read_int(cpu, offset+task)-offset

    #List traversal tasks for when we find the process list
    def process_list(self, cpu):
        task = self.next_task(cpu, self.parent_task)

        print(f"Traversing task list, starting at {task:#x}")
        while task != self.parent_task:
            pid = self.read_int(cpu, task+self.kinfo["task.pid_offset"]) 
            next_task = self.next_task(cpu, task)
            print(f"  {task:#x} has pid: {pid}, next: {next_task:#x}")
            #kallsyms does't always have this symbol
            if pid == 0:
                print(f"    found init_task at: {task:#x}") 
                if "task.init_addr" not in self.kinfo:
                    self.kinfo["task.init_addr"] = task
            task = next_task

    #PyPlugin - output our data on exit
    def uninit(self):
        print("\n\n--KERNELINFO-BEGIN--")
        for k, v in self.kinfo.items():
            print(k, "=", v)
            if "init_addr" in k or "per_cpu" in k:
                print("#", k, "=", hex(v))
        print("--KERNELINFO-END--")

if __name__ == "__main__":
    from pandare import Panda
    from sys import argv

    # Single arg of arch, defaults to i386
    arch = "i386" if len(argv) <= 1 else argv[1]
    panda = Panda(generic=arch)

    @panda.queue_blocking
    def run_my_cmd():
        panda.revert_sync("root")
        #panda.run_serial_cmd("uname -a",no_timeout=True)
        #panda.run_serial_cmd("cat /proc/self/syscall")
        panda.copy_to_guest("./user_prog")
        print(panda.run_serial_cmd("/root/user_prog/user_prog"))
        panda.end_analysis()

    panda.pyplugins.load(KernelInfo, args=dict({'kallsyms':kallsyms}))

    panda.run()
    #try:
    #    panda.run()
    #except KeyboardInterrupt:
    #    print("\nStopping for ctrl-c\n")

    #finally:
    #    print("Cleaning up...")

    #    panda.panda_finish() # Ensure we write pandalog
