#!/usr/bin/env python3
'''
qlog_example.py

This file demonstrates the qlog functionality:
- Dynamically enable/disable various types of logging
- Dynamically set/remove/replace the log file

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

panda.qlog.enable("panda")

@panda.cb_asid_changed
def asidchange(cpu, tb,asdf):
    global counter, on
    panda.qlog.log("hello from pypanda")
    if counter == 0:
        if not on:
            print("file")
            panda.qlog.output_to_file("fout")
        else:
            print("screen")
            # panda.qlog.tb_op_disable()
            panda.qlog.output_to_stderr()
        on = not on
    counter = (counter + 1) % 2
    from time import sleep
    sleep(1)
    return 0

panda.run()
