from pandare import Panda, blocking
panda = Panda(generic="x86_64")

#panda.load_plugin("syscalls2", args={"load-info": "True"})


tcg = True
if tcg:
    #panda.disable_tb_chaining()
    mode = "before_tcg_codegen"
else:
    panda.disable_tb_chaining()
    mode = "before_block_exec"


@panda.hook_symbol("libc", None, procname="uaf", name="hook_symbols", cb_type=mode)
def hook_symbols(cpu, tb, h):
    procname = panda.get_process_name(cpu)
    libname = panda.ffi.string(h.sym.section).decode("utf-8", 'ignore')
    symname = panda.ffi.string(h.sym.name).decode("utf-8", 'ignore')
    print(f"{procname} {libname} {symname} {panda.current_pc(cpu):x} {panda.arch.get_return_address(cpu):x}")


@panda.ppp("syscalls2","on_sys_write_enter")
def sys_write_enter(cpu, pc, fd, buf, count):
    if "uaf" in panda.get_process_name(cpu):
        print(f"OUT: {panda.read_str(cpu,buf).encode()} ({count})")

#@panda.ppp("proc_start_linux", "on_rec_auxv")
def rec_auxv(cpu, tb, auxv):
    procname = panda.get_process_name(cpu)
    print(f"got to proc_start_linux {procname} {panda.current_asid(cpu):x}")

#@panda.ppp("syscalls2", "on_all_sys_enter2")
def on_all_sys_enter(cpu, pc, call, ctx):
    if call.name != panda.ffi.NULL:
        print(f"{pc} {panda.ffi.string(call.name)}")


@blocking
def run_cmd():
    # First revert to root snapshot, then type a command via serial
    panda.revert_sync("root")
    panda.copy_to_guest("./target")
    print(panda.run_serial_cmd("uname -a"))
    print(panda.run_serial_cmd("cp /root/target/uaf /tmp/uaf && chmod +x /tmp/uaf"))
    #global hook_symbols
    #panda.hook_symbol("libc", None, procname="uaf", name="hook_symbols")
    #panda.record("aaaa")
    panda.flush_tb()
    print(panda.run_serial_cmd("/tmp/uaf"))
    #panda.end_record()
    print("Finding cat in cat's memory map:")
    maps = panda.run_serial_cmd("cat /proc/self/maps")
    for line in maps.split("\n"):
        if 'cat' in line:
            print(line)
    panda.end_analysis()

panda.queue_async(run_cmd)
panda.run()
#panda.run_replay("aaaa")