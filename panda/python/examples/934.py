from pandare import Panda, blocking
import pickle
from os.path import exists
panda = Panda(generic="x86_64")#,extra_args="-d out_asm")

#panda.load_plugin("syscalls2", args={"load-info": "True"})


tcg = False
tcg = True
if tcg:
    fname = "tcg"
    panda.disable_tb_chaining()
    mode = "before_tcg_codegen"
    print("running in tcg mode")
else:
    fname = "notcg"
    panda.disable_tb_chaining()
    mode = "before_block_exec"
    print("running in bbe mode")


if False: #exists("pick"):
    with open("pick","r") as f:
        to_hook = pickle.load(f)
else:
    to_hook = set()

with open("asdf","rb") as f:
    hookable = pickle.load(f)

for sym in hookable:
    @panda.hook(sym,enabled=True, cb_type=mode)
    def hook(cpu, tb, h):
        print(f"got to {panda.current_pc(cpu):x}")



#@panda.hook_symbol("libc", None, procname="uaf", name="hook_symbols", cb_type=mode, kernel=None)
#def hook_symbols(cpu, tb, h):
#    procname = panda.get_process_name(cpu)
#    libname = panda.ffi.string(h.sym.section).decode("utf-8", 'ignore')
#    symname = panda.ffi.string(h.sym.name).decode("utf-8", 'ignore')
#    print(f"{procname} {libname} {symname} {panda.current_pc(cpu):x} {panda.arch.get_return_address(cpu):x}")
#    to_hook.add(f"{procname} {libname} {symname} {panda.current_pc(cpu):x} {panda.arch.get_return_address(cpu):x}")
#    hookable.append(panda.current_pc(cpu))
#
#
#@panda.ppp("syscalls2","on_sys_write_enter")
#def sys_write_enter(cpu, pc, fd, buf, count):
#    if "uaf" in panda.get_process_name(cpu):
#        print(f"OUT: {panda.read_str(cpu,buf).encode()} ({count})")

lst = []

@panda.cb_before_tcg_codegen
def btc(cpu, tb):
    lst.append(panda.current_pc(cpu))


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
    #panda.flush_tb()
    print(panda.run_serial_cmd("/tmp/uaf"))
    #panda.end_record()
    print("Finding cat in cat's memory map:")
    maps = panda.run_serial_cmd("cat /proc/self/maps")
    for line in maps.split("\n"):
        if 'cat' in line:
            print(line)
    panda.end_analysis()

#panda.queue_async(run_cmd)
#panda.run()
panda.run_replay("aaaa")
#print(len(to_hook))
##print(to_hook)
#
#with open(fname, "w") as f:
#    for line in to_hook:
#        f.write(f"{line}\n")
#
#with open("btc", "w") as g:
#    for i in lst:
#        g.write(f"{i:x}\n")
#
#with open("asdf","wb") as f:
#    pickle.dump(hookable,f)