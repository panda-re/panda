from pandare import Panda

panda = Panda(generic="arm")

panda.load_plugin("callstack_instr")
panda.load_plugin("callwitharg")
panda.load_plugin("targetcmp")#, {"target_strings": "magic"})
#panda.load_plugin("targetcmp", {"target_strings": "whoami", "verbose": True})

@panda.ppp("targetcmp", "on_tcm")
def on_tcm(cpu, known, unknown):
   found = panda.ffi.string(known).decode() # The key we set
   other = panda.ffi.string(unknown).decode() # What it was compared to
   print(f"TCM detected comparison of {found} to {other}")
   #panda.arch.dump_regs(cpu)

@panda.queue_blocking
def driver():
    panda.revert_sync("root")

    t = panda.ffi.new("char[]", b"whoami")
    panda.plugins["targetcmp"].add_target(t)

    print(panda.run_serial_cmd("find /usr/bin/ -name 'who*'"))
    panda.end_analysis()

#panda.disable_tb_chaining()
panda.run()
