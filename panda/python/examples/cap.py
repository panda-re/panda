from pandare2 import Panda
from sys import argv
import capstone

panda = Panda(generic="i386")

@panda.queue_blocking
def qb():
    from time import sleep
    sleep(2)
    panda.run_monitor_cmd("q")
    

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

global i
i = 0

@panda.cb_vcpu_tb_trans
def vcpu_tb(id, tb):
    global i
    for insn in tb.insns:
        print(f"{insn.symbol}:  0x{insn.vaddr:x}:\t{insn.disas}")
    i += 1

print("entering main loop")
panda.run()
print("exiting")
