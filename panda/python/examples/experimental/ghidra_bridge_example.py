# forward your local port over ssh to remote machine
# or run headless, but less fun.
#ssh -R 4768:localhost:4768 target


from ghidra_bridge import GhidraBridge

b = GhidraBridge(namespace=globals(),response_timeout=1000)#,hook_import=True)

from pandare import Panda

def delete_all_memory_segments(memory, monitor):
    for block in memory.getBlocks(): 
        memory.removeBlock(block,monitor)

panda = Panda(generic="x86_64")
panda.load_plugin("syscalls2")


def read_memory(cpu, start, size):
    output = b""
    while size > 0:
        try:
            output = panda.virtual_memory_read(cpu, start, size)
            break
        except:
            size -= 0x100
    return output

def populate_ghidra(cpu, pc):
    tid = currentProgram.startTransaction("BRIDGE: Change Memory Sections")
    memory = currentProgram.getMemory()
    delete_all_memory_segments(memory,monitor)
    names = set()
    for mapping in panda.get_mappings(cpu):
        if mapping.file != panda.ffi.NULL:
            name = panda.ffi.string(mapping.file).decode()
        else:
            name = "[unknown]"
        while name in names:
            from random import randint
            name += ":"+hex(randint(0,100000000))
        names.add(name)
        memory.createInitializedBlock(name,toAddr(mapping.base),mapping.size,0,monitor,False)
        memory_read = read_memory(cpu,mapping.base,mapping.size)
        if memory_read:
            memory.setBytes(toAddr(mapping.base), read_memory(cpu,mapping.base, mapping.size))
    analyzeAll(currentProgram)
    #import ghidra.app.decompiler as decomp
    decomp = b.remote_import("ghidra.app.decompiler")
    # ## get the decompiler interface
    iface = decomp.DecompInterface()

    # ## decompile the function
    iface.openProgram(currentProgram)
    fn = getFunctionContaining(toAddr(pc))
    d = iface.decompileFunction(fn, 5, monitor)

    ## get the C code as string
    if not d.decompileCompleted():
        print(d.getErrorMessage())
    else:
        code = d.getDecompiledFunction()
        ccode = code.getC()
        print(ccode)

    setCurrentLocation(toAddr(pc))
    currentProgram.endTransaction(tid,True)

@panda.ppp("syscalls2", "on_sys_read_enter")
def on_sys_read_return(cpu, pc, fd, buf, count):
    proc = panda.plugins['osi'].get_current_process(cpu)
    procname = panda.ffi.string(proc.name) if proc != panda.ffi.NULL else "error"
    fname_ptr = panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
    fname = panda.ffi.string(fname_ptr) if fname_ptr != panda.ffi.NULL else "error"
    print(f"[PANDA] {procname} read from {fname}")
    if b"cat" in procname:
        populate_ghidra(cpu, pc)
        import ipdb
        ipdb.set_trace()

@panda.queue_async
def start():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("cat /etc/passwd"))
    panda.end_analysis()

panda.queue_async(start)
panda.run()
