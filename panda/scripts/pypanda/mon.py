#!/usr/bin/env python3

from pypanda import *
import qcows
import os
from enum import Enum
from sys import argv

# defaults to i386 unless arg1 is another arch string or qcow path
panda = Panda(qcow=qcows.qcow_from_arg())

class CBState(Enum):
    NOT_REQUESTED = 0
    PENDING = 1
    DONE = 2

mycb_state = CBState.NOT_REQUESTED

@panda.callback.after_machine_init
def machinit(env):
    global state
    progress("Machine initialized -- disabling chaining & reverting to booted snapshot\n")
    panda.disable_tb_chaining()
    panda.revert("root", now=True)
    pc = panda.current_pc(env)

@panda.callback.before_block_exec
def before_block_exec(env,tb):
    global mycb_state
    pc = panda.current_pc(env)

    if pc == 0xc10551d3 and mycb_state == CBState.NOT_REQUESTED:
        progress("Sending monitor command")
        mycb_state = CBState.PENDING
        panda.send_monitor_cmd("help info", mycb)

    if mycb_state == CBState.DONE:
        progress("After results callback. Quit")
        panda.stop()

    return 0

# This function is called with a string result from the monitor command
def mycb(result):
    global mycb_state
    mycb_state = CBState.DONE
    print("Mycb got result from monitor: {}".format(result))

# this is the initialiation for this plugin
@panda.callback.init
def init(handle):
    panda.register_callback(handle, panda.callback.after_machine_init, machinit)
    panda.register_callback(handle, panda.callback.before_block_exec, before_block_exec)
    return True

panda.load_python_plugin(init, "mon")
progress ("--- pypanda done with mon init")

panda.init()
progress ("--- pypanda done with INIT")

panda.run()
