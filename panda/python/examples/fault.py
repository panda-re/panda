from pandare import Panda

panda = Panda(generic="i386")
panda.load_plugin("syscalls2", {"load-info": True})

@panda.queue_blocking
def drive():
    panda.revert_sync('root')
    print(panda.run_serial_cmd("md5sum $(which whoami); find /etc/ | md5sum"))
    panda.end_analysis()

@panda.ppp("syscalls2", "on_all_sys_enter2")
def all_sys(cpu, pc, call, rp):
    args = panda.ffi.cast("target_ulong**", rp.args)

    print(f"{pc:#08x} (from block starting at {panda.current_pc(cpu):#08x}): {panda.ffi.string(call.name).decode()}(", end="")
    if call.nargs == 0:
        print(")", end="")

    just_dumped = False
    for i in range(call.nargs):
        print(f"{panda.ffi.string(call.argn[i]).decode()}=", end="")
        sep = ", " if i != call.nargs-1 else ")"

        if call.argt[i] not in [0x20, 0x21, 0x22]:
            val = int(panda.ffi.cast("unsigned int", args[i]))
            print(hex(val), end="")
        else:
            addr = int(panda.ffi.cast("unsigned int", args[i]))
            if addr < 0xFFFF:
                # Probably not a pointer?
                print(hex(addr), end="")
            else:
                try:
                    mem = panda.virtual_memory_read(cpu, addr, 8)
                except ValueError:
                    # ignore other args until fault is resolved
                    print(f"{addr:#x} => Can't read - INJECT PANDA PAGE FAULT") # newline

                    # DO FAULT
                    panda.libpanda.panda_page_fault(cpu, addr, pc)
                    # After fault is handled, we'll then re-run the syscall insn (and the TCG-based callback)
                    break

                # No fault
                print(f"{addr:#x} => {repr(panda.read_str(cpu, addr))}", end="")

        print(sep, end="") # , or )
    else:
        print()

@panda.ppp("syscalls2", "on_all_sys_return2")
def all_ret(cpu, pc, call, rp):
    rv = panda.arch.get_return_value(cpu)
    print(f"\t\t==> {rv:#x}")


# XXX: with TB chaining there's a gap between when the syscall happens and our injected PF is handled
#panda.disable_tb_chaining()
panda.run()
