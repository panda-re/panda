#!/usr/bin/env python3
from pandare import Panda
panda = Panda(generic="x86_64")

import logging
from rich.logging import RichHandler

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)

log = logging.getLogger("rich")
guest_file = "/home/luke/workspace/panda/panda/plugins/linjector/src/injectables/hello_world_x86_64"

elf = open(guest_file,"rb").read()

# panda.load_plugin("linjector", {"require_root":True, 
                            #    "guest_binary": guest_file})

# panda.load_plugin("hyperfuse")

MMAP2_NUM = 192

@panda.ppp("syscalls2","on_sys_execve_enter")
def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, env):
    fname = panda.read_str(cpu, fname_ptr)
    print(f'[PANDA] execve {fname}')

# @panda.ppp("syscalls2", "on_sys_write_return")
def write(cpu, pc, fd, buf, count):
    try:
        s = panda.read_str(cpu, buf, count)
    except ValueError:
        s = "error"
    if fd == 1 or fd == 2:
        log.info(f"SYS_OUT {s.strip()}")


SYS_MMAP = 9
SYS_MEMFD_CREATE = 319
SYS_WRITE = 1
SYS_FORK = 57
SYS_EXECVE = 59
SYS_CHDIR = 80

PAGE_SIZE = 0x1000
ALLOC_SIZE = PAGE_SIZE

mmap_return = None
memfd_return = None
saved_regs = None
sys_enter_pc = None
syscall_gen = None
asid = None

def do_mmap():
    PROT_READ = 4
    PROT_WRITE = 2
    PROT_EXEC = 1
    MAP_ANON = 0x20
    MAP_SHARED = 0x2
    return [SYS_MMAP, 0, ALLOC_SIZE, PROT_READ | PROT_WRITE , MAP_ANON | MAP_SHARED, 0xffffffffffffffff, 0]

def do_memfd_create(name):
    MEMFD_CLOEXEC = 1
    return [SYS_MEMFD_CREATE, name, MEMFD_CLOEXEC]

def do_write(cpu, memfd, mmap_addr, file_data):
    panda.virtual_memory_write(cpu, mmap_addr, file_data)
    return [SYS_WRITE, memfd, mmap_addr, len(file_data)]

def do_fork():
    return [SYS_FORK]

def do_execve(path, argv, envp):
    return [SYS_EXECVE, path, argv, envp]

def do_chdir(path):
    return [SYS_CHDIR, path]


def fork_rets(cpu, pc):
    retval = panda.arch.get_return_value(cpu)
    is_parent = retval != 0
    if is_parent:
        print(f"got fork in parent")
    else:
        print(f"got fork in child")
        global syscall_gen, asid
        asid = panda.current_asid(cpu)
        syscall_gen = do_child_syscall_handling()
        panda.ppp("syscalls2","on_all_sys_return")(sys_return)
        panda.disable_ppp("fork_rets")


def do_child_syscall_handling():
    print("in child syscall handler")
    cpu = panda.get_cpu()
    global memfd_return
    yield do_mmap()
    mmap_return = panda.arch.get_return_value(cpu)
    print(f"mmap returned {mmap_return:x}")

    print("doing chdir")
    yield do_chdir(mmap_return)
    chdir_return = panda.arch.get_return_value(cpu)
    print(f"chdir returned {chdir_return:x}")
    print(f"value: {panda.ffi.cast('target_long', chdir_return)}", )

    print("doing execve")
    file_name = "/proc/self/fd/"
    bytestr =bytes(file_name,"utf8")
    bytestr += bytes(chr(ord("0")+memfd_return),"utf8")
    bytestr += b"\x00\x00\x00\x00\x00\x00\x00\x00"
    panda.virtual_memory_write(cpu, mmap_return, bytestr)
    end_map_write = mmap_return + len(file_name)
    panda.disable_ppp("sys_return")
    yield do_execve(mmap_return, 0,0)
    print("finished")

def do_parent_syscall_handling():
    global mmap_return,memfd_return
    print("returning mmap")
    cpu = panda.get_cpu()
    yield do_mmap()
    mmap_return = panda.arch.get_return_value(cpu)
    print(f"mmap returned {mmap_return:x}")
    yield do_memfd_create(mmap_return)
    memfd_return = panda.arch.get_return_value(cpu)
    print(f"memfd_return {memfd_return}")

    pos = 0
    
    while len(elf) > pos:
        yield do_write(cpu, memfd_return, mmap_return, elf[pos:])
        pos += PAGE_SIZE
    
    panda.ppp("syscalls2", "on_sys_fork_return")(fork_rets)
    yield do_fork()

    print("finished")

def sys_return(cpu,pc,num,*args):
    global saved_regs
    if asid != panda.current_asid(cpu):
        return
    if saved_regs is None:
        saved_regs = panda.arch.get_regs(cpu)
    try:
        values = next(syscall_gen)
        print(values)
        for i in range(len(values)):
            panda.arch.set_arg(cpu, i, values[i], convention='syscall')
        panda.arch.set_pc(cpu, sys_enter_pc)
        panda.libpanda.cpu_loop_exit_noexc(cpu)
    except StopIteration:
        print("setting regs")
        panda.arch.set_regs(cpu,saved_regs)
        panda.disable_ppp("sys_return")


@panda.ppp("syscalls2", "on_all_sys_enter")
def on_all(cpu, pc, num, *args):
    global sys_enter_pc, sys_return, asid, syscall_gen
    sys_enter_pc = pc
    syscall_gen = do_parent_syscall_handling()
    asid = panda.current_asid(cpu)
    panda.ppp("syscalls2","on_all_sys_return")(sys_return)
    panda.disable_ppp("on_all")


@panda.queue_blocking
def driver():
    panda.revert_sync('root')
    print(panda.run_serial_cmd("cat /proc/cpuinfo"))
    panda.end_analysis()

panda.run()