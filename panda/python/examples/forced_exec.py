from pandare import Panda

panda = Panda(generic="mips")

@panda.queue_blocking
def driver():
  panda.revert_sync("root")
  print(panda.run_serial_cmd("whoami"))
  panda.end_analysis()

@panda.ppp("forcedexec", "on_branch")
def on_branch(cpu, tb, idx):
    # Let's flip  every branch in blocks with start PCs divisible by 0x30
    print("Branch at", hex(tb.pc))
    if (tb.pc % 0x30 == 0):
        print("FLIP IT")
        return True

    return False

panda.run()
