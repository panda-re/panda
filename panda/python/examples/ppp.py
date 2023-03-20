from pandare2 import Panda
from sys import argv
import capstone

panda = Panda(generic="arm")

@panda.queue_blocking
def qb():
    @panda.ppp("syscalls", "on_all_sys_enter")
    def on_all_syscalls(ev: "syscall_ev*"):
        print(f"Syscall {ev.callno} at 0x{ev.pc:x}")

    from time import sleep
    sleep(240)
    panda.run_monitor_cmd("q")

@panda.cb_vcpu_tb_trans
def x(a, b):
    pass

panda.run()
