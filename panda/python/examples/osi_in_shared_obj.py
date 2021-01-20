#!/usr/bin/env python3

from pandare import Panda, blocking, ffi

panda = Panda(generic="i386")
panda.load_plugin("osi")
bb_ctr = 0

@panda.cb_after_block_exec
def bbe(cpu, tb, exit_code):

    global bb_ctr

    if (not panda.in_kernel(cpu)) and (exit_code <= 1):
        bb_ctr += 1

        if (bb_ctr % 1000) == 0:
            proc = panda.plugins['osi'].get_current_process(cpu)
            if proc == ffi.NULL:
                return

            proc_name = ffi.string(proc.name).decode("utf-8")
            pc = panda.current_pc(cpu)
            in_dll = panda.plugins['osi'].in_shared_object(cpu, proc)
            print(f"{proc_name}@{pc:016x}, in SO? {in_dll}")

@blocking
def start():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("cat /etc/passwd"))
    panda.end_analysis()

panda.queue_async(start)
panda.run()
