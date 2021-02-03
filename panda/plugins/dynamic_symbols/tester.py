#%%
#%load_ext wurlitzer
from pandare import Panda
from rich import print, inspect
#arch = "x86_64"
arch = "i386"
#arch = "arm"
panda = Panda(generic=arch)
# %%
from os.path import exists

recording_name = "catetc4"+arch

if not exists(f"{recording_name}-rr-snp"):
    print("recordig did not exist")
    @panda.queue_blocking
    def do_stuff():
        panda.revert_sync("root")
        panda.run_monitor_cmd(f"begin_record {recording_name}")
        print(panda.run_serial_cmd("uname -a"))
        print(panda.run_serial_cmd("sleep 10 && cat /etc/passwd"))
        panda.run_monitor_cmd("end_record")
        panda.stop_run()
    panda.run()
else:
    print("recording exists. not remaking recording")
#

#@panda.cb_asid_changed
def asid_changed(cpu, old, new):
    symbol_to_hook = "malloc"
    symbol_to_hook = "printf"
    symbol = panda.ffi.new("char[]",bytes(symbol_to_hook,"utf8"))
    section_name = panda.ffi.NULL
    obj = panda.plugins["dynamic_symbols"].resolve_symbol(cpu, new, section_name, symbol)
    if obj.address != 0:
        print(f"{panda.get_process_name(cpu)} {panda.ffi.string(obj.name)} {panda.ffi.string(obj.section)} 0x{obj.address:x}")
    return 0
    


#panda.run_replay(recording_name)
# %%

hook_name_by_pc = {}

from string import ascii_lowercase

def proc_name(cpu):
    proc = panda.plugins['osi'].get_current_process(cpu)
    return ffi.string(proc.name)

def generic_hook(env,tb):
    if tb.pc in hook_name_by_pc:
        print(f"Made it to {hook_name_by_pc[tb.pc]}")
    else:
        print("Problem with generic_hook")
    return 0

allocated_regions = {}

def check_disable(current_asid,mad):
    for region in allocated_regions:
        asid,address = region
        size,enabled,phys = allocated_regions[region]
        if asid == current_asid:
            if not enabled:
                if mad.on_virtual:
                    if mad.addr <= address <= mad.addr + size:
                        print("disabling virtual")
                        mad.hook.enabled = False
                        del allocated_regions[region]
                else:
                    if mad.addr <= address <= mad.addr + size:
                        print("disabling virtual")
                        mad.hook.enabled = False
                        del allocated_regions[region]


def mem_writes_hooked_mallocs(cpu,mad):
    if mad.buf != ffi.NULL:
        buf_read = bytes([mad.buf[i] for i in range(mad.size)])
    else:
        buf_read = panda.physical_memory_read(mad.addr, mad.size)
    check_disable(panda.current_asid(cpu),mad)
    print(f"WRITE: {mad.addr:x} {panda.get_process_name(cpu)} {panda.in_kernel(cpu)} {mad.pc:x} {mad.size} {buf_read}")

hook_malloc_addrs = []
def hook_malloc(env, tb):
	# grab arguments ESP, arg1, arg2, arg3...
    size = get_arg(env, 1)
    ra = get_arg(env, 0)
    asid = panda.current_asid(env)
    global hook_malloc_addrs
    allocated_regions[(asid, ra)] = hook_return("malloc", env)
    if (asid,ra) not in hook_malloc_addrs:
        hook_malloc_addrs.append((asid,ra))
    print(f"{panda.get_process_name(env)} MALLOC (size:0x{size:x}) return 0x{ra:x}")
    return 0

malloc_vals = {}

realloc_vals = {}
def hook_realloc_return(env,tb):
    mem_val = get_retval(env)
    asid = panda.current_asid(env)
    mem_val_phys = panda.virt_to_phys(env,mem_val)
    ptr, size = realloc_vals[asid]
    print(f"{panda.get_process_name(env)} REALLOC RETURN VALUE: 0x{mem_val:x} {realloc_vals[asid]}")
    if (asid,ptr) in allocated_regions:
        del allocated_regions[(asid,ptr)]
    if (asid,mem_val) in allocated_regions:
        allocated_regions[(asid,mem_val)] = size
    else:
        allocated_regions[(asid,mem_val)] = size
    return 0

def hook_realloc(env, tb):
	# grab arguments ESP, arg1, arg2, arg3...
    ptr = get_arg(env, 1)
    size = get_arg(env, 2)
    ra = get_arg(env,0)
    asid = panda.current_asid(env)
    global hook_malloc_addrs
    if (asid,ra) not in hook_malloc_addrs:
        panda.hook(ra,enabled=True,kernel=False)(hook_realloc_return)
        hook_malloc_addrs.append((asid,ra))
    realloc_vals[asid] = ptr,size
    print(f"REALLOC {size} return 0x{ra:x}")
    return 0


def hook_free(env, tb):
	# grab arguments ESP, arg1, arg2, arg3...
    r = get_arg(env, 1)
    asid = panda.current_asid(env)

    if r != 0:
        if (asid,r) in allocated_regions:
            #size, enabled, phys = allocated_regions[(asid,r)]
            #allocated_regions[(asid,r)] = size, False, phys
            size = allocated_regions[(asid,r)]
            print(f"{panda.get_process_name(env)} FREE 0x{r:x} {size}")
            del allocated_regions[(asid,r)]
        else:
            print(f"missing allocated {r}")
    else:
        print("FREEING NULL")
        return 0
    return 0

def hook_exit(env, tb):
    ret_code = get_arg(env, 1)
    print(f'Process "{panda.get_process_name(env)}" exited with code {ret_code}')
    return 0

def hook_open(env,tb):
    arg1 = get_arg(env,1)
    file_name = panda.read_str(env,arg1)
    print(f"{panda.get_process_name(env)} OPEN: {file_name}")
    return 0

def hook_write(env,tb):
    fd = get_arg(env,1)
    buf = get_arg(env,2)
    n = get_arg(env,3)
    try:
        qq = panda.virtual_memory_read(env,buf, n)
    except:
        qq = b"[??]"
    print(f'{panda.get_process_name(env)} write {fd} "{qq}" (0x{buf:x}) {n:x}')
    return 0

def hook_read(env,tb):
    fd = get_arg(env,1)
    buf = get_arg(env, 2)
    print(f'{panda.get_process_name(env)} read {fd} 0x{buf:x}')
    return 0

def hook_close(env,tb):
    fd = get_arg(env,1)
    print(f'{panda.get_process_name(env)} close {fd} {fd_to_fname(env,fd)}')
    return 0

def get_arg(env, num):
    if arch == "i386":
        esp = panda.arch.get_reg(env,"ESP")
        r = panda.virtual_memory_read(env,esp+(4*num),4,fmt='int')
    elif arch == "x86_64":
        esp = panda.arch.get_reg(env, "RSP")
        r = panda.virtual_memory_read(env, esp+(8*num),8,fmt='int')
    elif arch == "arm":
        r_vals = ["LR", "R0", "R1", "R2","R3"]
        r = panda.arch.get_reg(env, r_vals[num - 1])
    else:
        r = 0
    return r

def get_retval(env):
    if arch == "i386":
        return panda.arch.get_reg(env, "EAX")
    elif arch == "x86_64":
        return panda.arch.get_reg(env, "RAX")
    elif arch == "arm":
        return panda.arch.get_reg(env, "R0")
    elif arch == "mips" or arch == "mipsel":
        return panda.arch.get_reg(env,"v0")
    return 0

def fd_to_fname(env, fd):
    proc = panda.plugins['osi'].get_current_process(env)
    procname = ffi.string(proc.name) if proc != ffi.NULL else "error"
    fname_ptr = panda.plugins['osi_linux'].osi_linux_fd_to_filename(env, proc, fd)
    fname = ffi.string(fname_ptr) if fname_ptr != ffi.NULL else "error"
    return fname

def hook_return(name, cpu):
    ra = get_arg(cpu, 0)
    val = [None]
    import uuid
    hook_name = uuid.uuid1()
    def inner_get_ret_val(env, tb):
        val[0] = get_retval(cpu) #panda.arch.get_reg(env,"EAX")
        print(f"{name} return 0x{val[0]:x}")
        panda.disable_hook(hook_name)
        return 0 
    panda.hook(ra,enabled=True,kernel=False,name=hook_name)(inner_get_ret_val)
    return val
    

def hook_function(env, f, s):
    symbol = panda.ffi.new("char[]",bytes(s,"utf8"))
    section_name = panda.ffi.NULL
    asid = panda.current_asid(env)
    obj = panda.plugins["dynamic_symbols"].resolve_symbol(env, asid, section_name, symbol)
    if obj.address != 0:
        print(f"{panda.get_process_name(env)} {panda.ffi.string(obj.name)} {panda.ffi.string(obj.section)} 0x{obj.address:x}")
        def g(env, tb):
            try:
                g = f(env, tb)
                if g != 0:
                    print(f"RESULT NOT EQUAL ZERO for {f} {g}")
            except Exception as e:
                print(e)
            return 0
        panda.hook(obj.address, enabled=True,kernel=False)(g)
    else:
        print(f"{s} no symbol :cry:")    

def hit(cpu, tb, mad):
    print("hit it")
    return 0

def program_start(env, tb, sh):
    print("got to program_start")
    return 0
    '''
    hook_function(env, hook_exit, "_Exit")
    hook_function(env, hook_open, "__open64")
    hook_function(env, hook_malloc, "__libc_malloc")
    hook_function(env, hook_free, "__libc_free")
    hook_function(env, hook_realloc, "__libc_realloc")
    hook_function(env, hook_read, "__read")
    hook_function(env, hook_write, "__write")
    return 0
    '''

from cffi import FFI
ffi = FFI()

ffi.cdef("""
         enum auxv_types {
AT_NULL             =  0 , //      ignored       /* End of vector */
AT_PHDR             =  3 , //      a_ptr         /* Program headers for program */
AT_PHENT            =  4 , //      a_val         /* Size of program header entry */
AT_PHNUM            =  5 , //      a_val         /* Number of program headers */
AT_PAGESZ           =  6 , //      a_val         /* System page size */
AT_BASE             =  7 , //      a_ptr         /* Base address of interpreter */
AT_FLAGS            =  8 , //      a_val         /* Flags */
AT_ENTRY            =  9 , //      a_ptr         /* Entry point of program */
AT_UID              =  11, //                    /* Real user ID (uid) */
AT_EUID             =  12, //                    /* Effective user ID (euid) */
AT_GID              =  13, //                    /* Real group ID (gid) */
AT_EGID             =  14, //                    /* Effective group ID (egid) */
AT_PLATFORM         =  15, //      a_ptr         /* String identifying platform. */
AT_HWCAP            =  16, //      a_val         /* Machine-dependent hints about 
                           //                 processor capabilities. */
AT_CLKTCK           =  17, //                    /* Frequency of times( ), always 100 */
AT_DCACHEBSIZE      =  19, //      a_val         /* Data cache block size */
AT_ICACHEBSIZE      =  20, //      a_val         /* Instruction cache block size */
AT_UCACHEBSIZE      =  21, //      a_val         /* Unified cache block size */
AT_IGNOREPPC        =  22, //                    /* Ignore this entry! */
AT_SECURE           =  23, //                    /* Boolean, was exec authorized to use 
                           //                 setuid or setgid */
AT_BASE_PLATFORM    =  24, //      a_ptr         /* String identifying real platforms */
AT_RANDOM           =  25, //                    /* Address of 16 random bytes */
AT_HWCAP2           =  26, //      a_val         /* More machine-dependent hints about 
                           //                 processor capabilities. */
AT_EXECFN           =  31, //                    /* File name of executable */
AT_SYSINFO_EHDR     =  33, //                    /* In many architectures, the kernel 
                           //                    provides a virtual dynamic shared 
                           //                    object (VDSO) that contains a function 
                           //                    callable from the user state.   
                           //                    AT_SYSINFO_EHDR is the address of the
                           //                    VDSO header that is used by the
                           //                    dynamic linker to resolve function 
                           //                    symbols with the VDSO. */
AT_L1I_CACHESIZE    =  40, //                    /* Cache sizes and geometries. */
AT_L1I_CACHEGEOMETRY=  41, //
AT_L1D_CACHESIZE    =  42, //
AT_L1D_CACHEGEOMETRY=  43, //
AT_L2_CACHESIZE     =  44, //
AT_L2_CACHEGEOMETRY =  45, //
AT_L3_CACHESIZE     =  46, //
AT_L3_CACHEGEOMETRY =  47, //
};

         
         """)


    
#@panda.ppp("syscalls2","on_sys_execve_enter")
def execve_enter(cpu, pc, pathname, argv, envp):
    print("hit sys_execve")
    from string import ascii_lowercase
    from random import choice
    
    # this makes a random string. We just need a unique key.
    funcname = ''.join(choice(ascii_lowercase) for i in range(20))

    '''
    We parse the auxiliary vector for the program entrypoint.
    
    We take that value and set a new hook for program_start above.
    '''
    @panda.cb_before_block_exec(name=funcname, enabled=True)
    def grab_auxiliary_vector(cpu, tb):
        if not panda.in_kernel(cpu):
            sp = panda.current_sp(cpu)
            buf_size = panda.ffi.sizeof("target_ulong")
            stack = panda.virtual_memory_read(cpu, sp, 50*buf_size)
            pybuf = panda.ffi.from_buffer(stack)
            ptrlist = panda.ffi.cast("target_ulong*", pybuf)
            argc = ptrlist[0]
            arglist = []
            ptrlistpos = 1
            while True:
                ptr = ptrlist[ptrlistpos]
                ptrlistpos += 1
                if ptr != 0: 
                    try:
                        value = panda.read_str(cpu, ptr)
                        arglist.append(value)
                    except:
                        arglist.append("?")
                else:
                    break
            print(f"arglist: {' '.join(arglist)}")

            envlist = []

            while True:
                ptr = ptrlist[ptrlistpos]
                ptrlistpos += 1
                if ptr != 0:
                    try: 
                        value = panda.read_str(cpu, ptr)
                        envlist.append(value)
                    except:
                        envlist.append("?")
                else:
                    break
            print(f"envlist: {','.join(envlist)}")

            print("Auxiliary vector:")
            while True:
                auxv_entrynum = ptrlist[ptrlistpos]
                auxv_entryval = ptrlist[ptrlistpos+1]
                ptrlistpos += 2
                entrynumstr = ffi.string(ffi.cast("enum auxv_types", auxv_entrynum))
                if entrynumstr == "AT_NULL":
                    break
                elif entrynumstr == "AT_ENTRY":
                    print(f"{entrynumstr} {hex(auxv_entryval)}")
                    global program_start
                    panda.hook(auxv_entryval, kernel=False, enabled=True, name=f"{proc_name(cpu).decode()}:program_start")(program_start)
                    break
                else:
                    print(f"{entrynumstr} {hex(auxv_entryval)}")

            panda.disable_callback(funcname)

#@panda.hook_symbol("libc", "_Exit")
def get_exit(cpu, tb, h):
    print(f"got to exit {panda.get_process_name(cpu)}")
    return False


#@panda.hook_symbol("libc", "__read")
def get_exit(cpu, tb, h):
    print(f"got to read {panda.get_process_name(cpu)}")
    return False

previous_buf_addr = None
def hook_read_return(env, tb, h):
    ret = get_retval(env)
    try:
        retstr = panda.read_str(env, previous_buf_addr)
    except:
        retstr = "?"
    print(f"hook ret \"{retstr}\"(0x{ret:x})")
    h.enabled = False
    return 0


    
@panda.hook_symbol("libc", "__read")
def hook_read(env,tb, h):
    fd = get_arg(env,1)
    buf = get_arg(env, 2)
    global previous_buf_addr
    previous_buf_addr = buf
    print(f'{panda.get_process_name(env)} read {fd} 0x{buf:x}')
    #ra = get_arg(env, 0)
    #import uuid
    #hook_name = uuid.uuid1()
    #panda.hook(ra,enabled=True,kernel=False,name=hook_name, asid=panda.current_asid(env), cb="before_block_exec_invalidate_opt")(hook_read_return)

panda.run_replay(recording_name)