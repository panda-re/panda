from pandare import Panda

panda = Panda(generic="i386")

@panda.queue_blocking
def guest_interaction():
    panda.revert_sync("root")
    for cmd in ["ls -la", "whoami", "time ls -la"]:
        print(f"{cmd} {panda.run_serial_cmd('LD_SHOW_AUXV=1 '+cmd)}")
    panda.end_analysis()

@panda.ppp("proc_start_linux", "on_rec_auxv")
def recv_auxv(cpu, tb, auxv):
    procname = panda.ffi.string(auxv.procname)
    print(f"started proc {procname} {auxv.phdr:x} {auxv.entry:x}")

panda.run()
