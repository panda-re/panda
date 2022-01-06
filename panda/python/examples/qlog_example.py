#!/usr/bin/env python3
'''
asid.py

To give the machine something to do we queue an asynchronous command which
reverts the machine to a snapshot, runs a command, and then ends.

In our analysis we register the asid_changed callback and prints the ASID
output when it changes.

Run with: python3 after_init.py
'''
from sys import argv
from pandare import Panda

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@panda.queue_blocking
def run_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))
    panda.end_analysis()

counter = 0
on = False

@panda.cb_before_block_exec
def asidchange(cpu, tb):
    global counter, on
    if counter == 0:
        if not on:
            print("enabling")
            panda.qlog.output_to_file("fout")
            panda.qlog.tb_op_enable()
        else:
            print("disabling")
            panda.qlog.tb_op_disable()
        on = not on
    from time import sleep
    # sleep(1)
    counter = (counter + 1) % 1000000

panda.run()
