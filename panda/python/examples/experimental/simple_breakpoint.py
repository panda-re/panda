#!/usr/bin/env python3
'''
TODO: We don't currently have a way to unset the breakpoint so you get stuck there :(
'''

from sys import argv
from pandare import Panda

panda = Panda(generic="i386", extra_args=["-s", "-S"])

@blocking
def run_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))
    panda.end_analysis()

@panda.cb_asid_changed()
def asidchange(env, old_asid, new_asid):
    '''
    On ASID change, print and enable next_bb_break fn
    '''
    if old_asid != new_asid:
        print("Asid changed from %d to %d. Triggering breakpoint..." % (old_asid, new_asid))
        panda.enable_callback("next_bb_break")
    return 0


@panda.cb_before_block_exec_invalidate_opt(enabled=False)
def next_bb_break(cpu, tb):
    '''
    When enabled, add a breakpoint to the start of the next block we exec
    Then disable this callbac
    '''
    print("SET breakpoint")
    panda.set_breakpoint(cpu, panda.current_pc(cpu))

    panda.disable_callback("next_bb_break")
    return True

panda.queue_async(run_cmd)

panda.run()
