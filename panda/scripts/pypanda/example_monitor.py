#!/usr/bin/env python3

from pypanda import *
import qcows
import os
from enum import Enum
from sys import argv

# defaults to i386 unless arg1 is another arch string or qcow path
panda = Panda(qcow=qcows.qcow_from_arg())

class State(Enum):
    CB_NOT_REQUESTED = 0
    CB_PENDING = 1
    CB_DONE = 2
    QUIT_PENDING = 3

state = State.CB_NOT_REQUESTED

@panda.callback.after_machine_init
def machinit(env):
    progress("Machine initialized -- disabling chaining & reverting to booted snapshot\n")
    panda.disable_tb_chaining()
    panda.revert("root", now=True)
    pc = panda.current_pc(env)

@panda.callback.before_block_exec
def before_block_exec(env,tb):
    global state
    pc = panda.current_pc(env)

    if pc == 0xc10551d3 and state == State.CB_NOT_REQUESTED:
        progress("Sending monitor command")
        state = State.CB_PENDING
        panda.send_monitor_cmd("info mem", info_mem_cb)

    if state == State.CB_DONE:
        progress("After results callback. Quit via monitor")
        panda.send_monitor_cmd("quit")
        state = State.QUIT_PENDING

    return 0

# This function is called with a string result from the monitor command
def info_mem_cb(result):
    global state
    state = State.CB_DONE

    # Get info mem results, sorted by size of allocation
    lines = [x for x in result.split("\n") if x]
    lines.sort(key=lambda x: int(x.split(" ")[-2], 16) if len(x.split(" ")) >= 3 else 0)

    print("info mem returned information on {} allocations!\n\t Biggest: {}\n\t" \
            "Smallest: {}".format(len(lines), lines[-1], lines[0]))

# this is the initialiation for this plugin
@panda.callback.init
def init(handle):
    panda.register_callback(handle, panda.callback.after_machine_init, machinit)
    panda.register_callback(handle, panda.callback.before_block_exec, before_block_exec)
    return True

panda.load_python_plugin(init, "mon")
progress ("--- pypanda done with mon plugin init")

panda.init()
progress ("--- pypanda done with init")

panda.run()
