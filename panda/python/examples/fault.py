from pandare import Panda

panda = Panda(generic="arm")
#panda = Panda(generic="i386")
#panda = Panda(generic="x86_64")
#panda = Panda(generic="mips64")

panda.load_plugin("syscalls2", {"load-info": True})

@panda.queue_blocking
def drive():
    panda.revert_sync('root')
    print(panda.run_serial_cmd("md5sum $(which whoami); find /etc/ | md5sum; apt-get update -yy"))
    panda.end_analysis()

last_fault = None
def fault(panda, cpu, addr, pc):
    global last_fault
    if last_fault == addr:
        raise MemoryError(f"Double fault of {addr:x}")
    last_fault = addr
    panda.libpanda.panda_page_fault(cpu, addr, pc)


@panda.ppp("syscalls2", "on_all_sys_enter2")
def all_sys(cpu, pc, call, rp):
    args = panda.ffi.cast("target_ulong**", rp.args)

    sc_name = panda.ffi.string(call.name).decode() if call.name != panda.ffi.NULL else 'err'
    print(f"{pc:#08x} (from block starting at {panda.current_pc(cpu):#08x}): {sc_name}(", end="")
    if call.nargs == 0:
        print(")", end="")

    just_dumped = False
    for i in range(call.nargs):
        print(f"{panda.ffi.string(call.argn[i]).decode()}=", end="")
        sep = ", " if i != call.nargs-1 else ")"

        if call.argt[i] not in [0x20, 0x21, 0x22]:
            val = int(panda.ffi.cast("unsigned int", args[i]))
            print(hex(val), end="")
            continue

        # It's a pointer type
        addr = int(panda.ffi.cast("unsigned int", args[i]))
        if addr < 0xFFFF:
            # Probably not a pointer?
            print(hex(addr), end="")
        else:
            try:
                s = panda.read_str(cpu, addr)
            except ValueError:
                # This argument can't be read - let's raise a fault on it
                if last_fault != addr:
                    print(f"{addr:#x} => Can't read - INJECT PANDA PAGE FAULT") # newline
                    fault(panda, cpu, addr, pc)
                    return # Raised a fault, hope it's gonna work
                else:
                    s = "still can't read"

            # No fault
            print(f"{addr:#x} => {repr(s)}", end="")

        print(sep, end="") # , or )

@panda.ppp("syscalls2", "on_all_sys_return2")
def all_ret(cpu, pc, call, rp):
    rv = panda.arch.get_return_value(cpu)
    print(f"\t\t==> {rv:#x}")


# XXX: with TB chaining there's a gap between when the syscall happens and our injected PF is handled
#panda.disable_tb_chaining()
panda.run()
