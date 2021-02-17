from pandare import Panda
'''
Whenever the process changes, print it's ASID and name
'''

panda = Panda(generic='x86_64')

def _active_proc_name(cpu):
    proc = panda.plugins['osi'].get_current_process(cpu)
    if proc == panda.ffi.NULL: return ""
    return panda.ffi.string(proc.name).decode("utf8", errors="ignore")

@panda.queue_blocking
def driver():
    panda.revert_sync("root")
    for x in range(10):
        print("Guest outputs:", panda.run_serial_cmd(f"echo {x}"))
    panda.end_analysis()

@panda.ppp("osi", "on_task_change")
def taskchange(cpu):
    asid = panda.current_asid(cpu)
    name = _active_proc_name(cpu)
    print(f"Task change: 0x{asid:x} {name}")

panda.run()
